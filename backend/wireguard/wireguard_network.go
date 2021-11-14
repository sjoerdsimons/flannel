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
	"encoding/json"
	"fmt"
	"net"
	"sync"

	"github.com/flannel-io/flannel/backend"
	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/subnet"
	"golang.org/x/net/context"
	log "k8s.io/klog"
)

const (
	/*
		20-byte IPv4 header or 40 byte IPv6 header
		8-byte UDP header
		4-byte type
		4-byte key index
		8-byte nonce
		N-byte encrypted data
		16-byte authentication tag
	*/
	overhead = 80
)

type network struct {
	dev      *wgDevice
	extIface *backend.ExternalInterface
	lease    *subnet.Lease
	sm       subnet.Manager
}

func newNetwork(sm subnet.Manager, extIface *backend.ExternalInterface, dev *wgDevice, lease *subnet.Lease) (*network, error) {
	n := &network{
		dev:      dev,
		extIface: extIface,
		lease:    lease,
		sm:       sm,
	}

	return n, nil
}

func (n *network) Lease() *subnet.Lease {
	return n.lease
}

func (n *network) MTU() int {
	return n.extIface.Iface.MTU - overhead
}

func (n *network) Run(ctx context.Context) {
	wg := sync.WaitGroup{}

	log.Info("Watching for new subnet leases")
	events := make(chan []subnet.Event)
	wg.Add(1)
	go func() {
		subnet.WatchLeases(ctx, n.sm, n.lease, events)
		wg.Done()
	}()

	defer wg.Wait()

	for {
		select {
		case evtBatch := <-events:
			n.handleSubnetEvents(evtBatch)

		case <-ctx.Done():
			return
		}
	}
}

type wireguardLeaseAttrs struct {
	PublicKey string
}

// Select the endpoint address that is most likely to allow for a successful
// connection.
// If both ipv4 and ipv6 addresses are provided:
//   * Prefer ipv4 if the remote endpoint has a public ipv4 address
//     and the external iface has an ipv4 address as well. Anything with
//     an ipv4 address can likely connect to the public internet.
//   * Use ipv6 if the remote endpoint has a publc address and the local
//     interface has a public address as well. In which case it's likely that
//     a connection can be made. The local interface having just an link-local
//     address will only have a small chance of succeeding (ipv6 masquarading is
//     very rare)
//   * If neither is true default to ipv4 and cross fingers.
func (n *network) selectPublicEndpoint(ip4 *ip.IP4, ip6 *ip.IP6) string {
	if ip4 != nil && ip6 == nil {
		return ip4.String()
	}

	if ip4 == nil && ip6 != nil {
		return fmt.Sprintf("[%s]", ip6.String())
	}

	if !ip4.IsPrivate() && n.extIface.ExtAddr != nil {
		return ip4.String()
	}

	if !ip6.IsPrivate() && n.extIface.ExtV6Addr != nil && !ip.FromIP6(n.extIface.ExtV6Addr).IsPrivate() {
		return fmt.Sprintf("[%s]", ip6.String())
	}

	return ip4.String()
}

func (n *network) handleSubnetEvents(batch []subnet.Event) {
	for _, event := range batch {
		switch event.Type {
		case subnet.EventAdded:
			if event.Lease.Attrs.BackendType != "wireguard" {
				log.Warningf("Ignoring non-wireguard subnet: type=%v", event.Lease.Attrs.BackendType)
				continue
			}

			publicEndpoint := fmt.Sprintf("%s:%d",
				n.selectPublicEndpoint(&event.Lease.Attrs.PublicIP, event.Lease.Attrs.PublicIPv6),
				n.dev.attrs.listenPort)

			var wireguardAttrs wireguardLeaseAttrs
			var subnets []net.IPNet
			if event.Lease.EnableIPv4 && n.dev != nil {
				log.Infof("Subnet added: %v", event.Lease.Subnet)

				if len(event.Lease.Attrs.BackendData) > 0 {
					if err := json.Unmarshal(event.Lease.Attrs.BackendData, &wireguardAttrs); err != nil {
						log.Errorf("failed to unmarshal BackendData: %v", err)
						continue
					}
				}

				subnets = append(subnets, *event.Lease.Subnet.ToIPNet())
			}

			if event.Lease.EnableIPv6 {
				log.Infof("Subnet added: %v", event.Lease.IPv6Subnet)

				if len(event.Lease.Attrs.BackendV6Data) > 0 {
					if err := json.Unmarshal(event.Lease.Attrs.BackendV6Data, &wireguardAttrs); err != nil {
						log.Errorf("failed to unmarshal BackendData: %v", err)
						continue
					}
				}

				subnets = append(subnets, *event.Lease.IPv6Subnet.ToIPNet())
			}

			if err := n.dev.addPeer(
				publicEndpoint,
				wireguardAttrs.PublicKey,
				subnets); err != nil {
				log.Errorf("failed to setup peer (%s): %v", wireguardAttrs.PublicKey, err)
			}

		case subnet.EventRemoved:

			if event.Lease.Attrs.BackendType != "wireguard" {
				log.Warningf("Ignoring non-wireguard subnet: type=%v", event.Lease.Attrs.BackendType)
				continue
			}

			var wireguardAttrs wireguardLeaseAttrs
			if event.Lease.EnableIPv4 {
				log.Info("Subnet removed: ", event.Lease.Subnet)
				if len(event.Lease.Attrs.BackendData) > 0 {
					if err := json.Unmarshal(event.Lease.Attrs.BackendData, &wireguardAttrs); err != nil {
						log.Errorf("failed to unmarshal BackendData: %v", err)
						continue
					}
				}

				if err := n.dev.removePeer(
					wireguardAttrs.PublicKey,
				); err != nil {
					log.Errorf("failed to remove ipv4 peer (%s): %v", wireguardAttrs.PublicKey, err)
				}
			}

			if event.Lease.EnableIPv6 {
				log.Info("Subnet removed: ", event.Lease.IPv6Subnet)
				if len(event.Lease.Attrs.BackendV6Data) > 0 {
					if err := json.Unmarshal(event.Lease.Attrs.BackendV6Data, &wireguardAttrs); err != nil {
						log.Errorf("failed to unmarshal BackendData: %v", err)
						continue
					}
				}

				if err := n.dev.removePeer(
					wireguardAttrs.PublicKey,
				); err != nil {
					log.Errorf("failed to remove ipv6 peer (%s): %v", wireguardAttrs.PublicKey, err)
				}
			}

		default:
			log.Error("Internal error: unknown event type: ", int(event.Type))
		}
	}
}
