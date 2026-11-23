package translate

import (
	"fmt"
	"net/netip"
	"strings"
)

// EgressMap is the public subnet an AWS VPC needs for its NAT gateways. An
// Azure NAT gateway sits in no subnet; an AWS one sits in a subnet that
// routes to an internet gateway, so that subnet's range is a choice.
type EgressMap struct {
	// Subnet is the range of the public subnet (10.20.255.0/28): inside the
	// network's range, outside every subnet of it, a /28 or wider.
	Subnet string `json:"subnet"`
	// Zone is the availability zone it, and so the NAT gateways, are in;
	// network.zone when left out.
	Zone string `json:"zone,omitempty"`
}

func (m Map) validateRouting() error {
	n := m.Network
	if n == nil {
		return nil
	}
	switch n.DefaultOutbound {
	case "", "nat":
	default:
		return fmt.Errorf("map: network.defaultOutbound: %q is not nat", n.DefaultOutbound)
	}
	if m.To != "aws" && len(n.Egress) > 0 {
		return fmt.Errorf("map: network.egress is for aws: Cloud NAT needs no subnet of its own")
	}
	for _, k := range sortedMapKeys(n.Egress) {
		e := n.Egress[k]
		if strings.Count(k, "/") != 1 {
			return fmt.Errorf("map: network.egress: %q is not group/network", k)
		}
		if p, err := netip.ParsePrefix(e.Subnet); err != nil || !p.Addr().Is4() || p != p.Masked() {
			return fmt.Errorf("map: network.egress.%s.subnet: %q is not an IPv4 range (10.20.255.0/28)", k, e.Subnet)
		}
	}
	return nil
}

// egressFor is the map's public subnet for a network (group/network).
func (m Map) egressFor(key string) (EgressMap, bool) {
	if m.Network == nil {
		return EgressMap{}, false
	}
	for k, e := range m.Network.Egress {
		if strings.EqualFold(k, key) {
			return e, true
		}
	}
	return EgressMap{}, false
}
