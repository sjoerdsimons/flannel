// Copyright 2021 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package wireguard

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	log "k8s.io/klog"
)

type wgDeviceAttrs struct {
	listenPort int
	privateKey *wgtypes.Key
	publicKey  *wgtypes.Key
	psk        *wgtypes.Key
	keepalive  *time.Duration
	name       string
}

type wgDevice struct {
	link  *netlink.GenericLink
	attrs *wgDeviceAttrs
}

func writePrivateKey(path string, content string) error {
	dir, _ := filepath.Split(path)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}

	err = os.Chmod(path, 0400)
	if err != nil {
		return err
	}

	_, err = f.WriteString(content)
	if err != nil {
		return err
	}

	f.Close()

	return nil
}

func (devAttrs *wgDeviceAttrs) setupKeys(psk string) error {
	keyFile := "/run/flannel/wgkey"

	envKeyFile, envExists := os.LookupEnv("WIREGUARD_KEY_FILE")
	if envExists {
		keyFile = envKeyFile
	}

	if _, err := os.Stat(keyFile); errors.Is(err, os.ErrNotExist) {
		privateKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("could not generate private key: %v", err)
		}
		devAttrs.privateKey = &privateKey

		publicKey := privateKey.PublicKey()
		devAttrs.publicKey = &publicKey

		err = writePrivateKey(keyFile, privateKey.String())
		if err != nil {
			return fmt.Errorf("could not write key file: %v", err)
		}
	} else {
		data, err := ioutil.ReadFile(keyFile)
		if err != nil {
			return err
		}
		privateKey, err := wgtypes.ParseKey(string(data))
		if err != nil {
			return fmt.Errorf("could not parse private key from file: %v", err)
		}
		devAttrs.privateKey = &privateKey
		publicKey := privateKey.PublicKey()
		devAttrs.publicKey = &publicKey
	}

	if psk != "" {
		presharedKey, err := wgtypes.ParseKey(psk)
		if err != nil {
			return fmt.Errorf("could not parse psk: %v", err)
		}
		devAttrs.psk = &presharedKey
	}

	return nil
}

func newWGDevice(devAttrs *wgDeviceAttrs, ctx context.Context, wg *sync.WaitGroup) (*wgDevice, error) {
	la := netlink.LinkAttrs{
		Name: devAttrs.name,
	}
	link := &netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}

	link, err := ensureLink(link)
	if err != nil {
		return nil, err
	}

	dev := wgDevice{
		link:  link,
		attrs: devAttrs,
	}

	// This code runs before flannel terminates.
	// We remove the device to undo any change we did to the system.
	wg.Add(1)
	go func() {
		select {
		case <-ctx.Done():
			dev.remove()
			log.Infof("Removed wireguard device %v", dev.attrs.name)
			wg.Done()
		}
	}()

	return &dev, nil
}

func ensureLink(wglan *netlink.GenericLink) (*netlink.GenericLink, error) {
	err := netlink.LinkAdd(wglan)
	if err == syscall.EEXIST {
		existing, err := netlink.LinkByName(wglan.Name)
		if err != nil {
			return nil, err
		}

		log.Warningf("%q already exists; recreating device", wglan.Name)
		err = netlink.LinkDel(existing)
		if err != nil {
			return nil, err
		}

		err = netlink.LinkAdd(wglan)
		if err != nil {
			return nil, fmt.Errorf("could not create wireguard interface:  %v", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("could not create wireguard interface:  %v", err)
	}

	_, err = netlink.LinkByIndex(wglan.Index)
	if err != nil {
		return nil, fmt.Errorf("can't locate created wireguard device with index %v", wglan.Index)
	}

	return wglan, nil
}

func (dev *wgDevice) remove() error {
	err := netlink.LinkDel(dev.link)
	if err != nil {
		return fmt.Errorf("could not remove wireguard device: %v", err)
	}
	return nil
}

func (dev *wgDevice) Configure(devIP ip.IP4, flannelnet ip.IP4Net) error {
	wgcfg := wgtypes.Config{
		PrivateKey:   dev.attrs.privateKey,
		ListenPort:   &dev.attrs.listenPort,
		ReplacePeers: true,
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to open wgctrl: %v", err)
	}

	err = client.ConfigureDevice(dev.attrs.name, wgcfg)
	if err != nil {
		return fmt.Errorf("failed to configure device %v", err)
	}

	net := ip.IP4Net{IP: devIP, PrefixLen: 32}
	err = ip.EnsureV4AddressOnLink(net, flannelnet, dev.link)
	if err != nil {
		return fmt.Errorf("failed to ensure address of interface %s: %s", dev.link.Attrs().Name, err)
	}

	err = netlink.LinkSetUp(dev.link)
	if err != nil {
		return fmt.Errorf("failed to set interface %s to UP state: %s", dev.link.Attrs().Name, err)
	}

	route := netlink.Route{
		LinkIndex: dev.link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       flannelnet.ToIPNet(),
	}
	err = netlink.RouteAdd(&route)
	if err != nil {
		return fmt.Errorf("failed to add route %s: %s", dev.link.Attrs().Name, err)
	}

	client.Close()

	return nil
}

func (dev *wgDevice) ConfigureV6(devIP *ip.IP6, flannelnet ip.IP6Net) error {
	wgcfg := wgtypes.Config{
		PrivateKey:   dev.attrs.privateKey,
		ListenPort:   &dev.attrs.listenPort,
		ReplacePeers: true,
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to open wgctrl: %v", err)
	}

	err = client.ConfigureDevice(dev.attrs.name, wgcfg)
	if err != nil {
		return fmt.Errorf("failed to configure device %v", err)
	}

	net := ip.IP6Net{IP: devIP, PrefixLen: 128}
	err = ip.EnsureV6AddressOnLink(net, flannelnet, dev.link)
	if err != nil {
		return fmt.Errorf("failed to ensure address of interface %s: %s", dev.link.Attrs().Name, err)
	}

	err = netlink.LinkSetUp(dev.link)
	if err != nil {
		return fmt.Errorf("failed to set interface %s to UP state: %s", dev.link.Attrs().Name, err)
	}

	route := netlink.Route{
		LinkIndex: dev.link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       flannelnet.ToIPNet(),
	}
	err = netlink.RouteAdd(&route)
	if err != nil {
		return fmt.Errorf("failed to add route %s: %s", dev.link.Attrs().Name, err)
	}

	client.Close()

	return nil
}

func (dev *wgDevice) addPeer(publicEndpoint string, peerPublicKeyRaw string, peerSubnet *net.IPNet) error {
	udpEndpoint, err := net.ResolveUDPAddr("udp", publicEndpoint)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	peerPublicKey, err := wgtypes.ParseKey(peerPublicKeyRaw)
	if err != nil {
		return fmt.Errorf("failed to parse publicKey: %v", err)
	}

	wgcfg := wgtypes.Config{
		PrivateKey:   dev.attrs.privateKey,
		ListenPort:   &dev.attrs.listenPort,
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:                   peerPublicKey,
				PresharedKey:                dev.attrs.psk,
				PersistentKeepaliveInterval: dev.attrs.keepalive,
				Endpoint:                    udpEndpoint,
				ReplaceAllowedIPs:           true,
				AllowedIPs: []net.IPNet{
					*peerSubnet,
				},
			},
		}}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to open wgctrl: %v", err)
	}

	err = client.ConfigureDevice(dev.attrs.name, wgcfg)
	if err != nil {
		return fmt.Errorf("failed to configure device %v", err)
	}

	client.Close()

	// Remove peers from this endpoint with different public keys
	dev.cleanupEndpointPeers(udpEndpoint, peerPublicKeyRaw)

	return nil
}

func (dev *wgDevice) cleanupEndpointPeers(udpEndpoint *net.UDPAddr, latestPublicKeyRaw string) error {

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to open wgctrl: %v", err)
	}

	currentDev, err := client.Device(dev.attrs.name)
	if err != nil {
		return fmt.Errorf("failed to open device: %v", err)
	}

	peers := []wgtypes.PeerConfig{}
	for _, peer := range currentDev.Peers {
		if peer.Endpoint.IP.Equal(udpEndpoint.IP) {
			if peer.PublicKey.String() != latestPublicKeyRaw {
				removePeer := wgtypes.PeerConfig{
					PublicKey: peer.PublicKey,
					Remove:    true,
				}
				peers = append(peers, removePeer)
			}
		}
	}

	wgcfg := wgtypes.Config{
		PrivateKey:   dev.attrs.privateKey,
		ListenPort:   &dev.attrs.listenPort,
		ReplacePeers: false,
		Peers:        peers,
	}

	err = client.ConfigureDevice(dev.attrs.name, wgcfg)
	if err != nil {
		return fmt.Errorf("failed to cleanup peers %v", err)
	}

	client.Close()

	return nil
}

func (dev *wgDevice) removePeer(peerPublicKeyRaw string) error {
	peerPublicKey, err := wgtypes.ParseKey(peerPublicKeyRaw)
	if err != nil {
		return fmt.Errorf("failed to parse publicKey: %v", err)
	}

	wgcfg := wgtypes.Config{
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: peerPublicKey,
				Remove:    true,
			},
		}}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to open wgctrl: %v", err)
	}

	err = client.ConfigureDevice(dev.attrs.name, wgcfg)
	if err != nil {
		return fmt.Errorf("failed to remove peer %v", err)
	}

	client.Close()

	return nil
}
