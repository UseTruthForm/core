package translate

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// A virtual network's address space as a VPC's CIDR blocks. An Azure
// network holds any number of ranges of any width; a VPC is created with
// one block of /16 to /28 and takes more of the same widths afterwards
// (AWS::EC2::VPCCidrBlock). So a range wider than /16 is written as its
// /16s, and a second range as a second block: the same addresses, in
// more pieces. AWS adds a local route for each, so they route to each
// other as one network.
//
// Which blocks may sit together, and which must be the first, is AWS's
// table "IPv4 CIDR block association restrictions":
// https://docs.aws.amazon.com/vpc/latest/userguide/vpc-cidr-blocks.html

const (
	awsVPCBlock = "AWS::EC2::VPCCidrBlock"
	// vpcBlockQuota is AWS's default for "IPv4 CIDR blocks per VPC", and
	// vpcBlockMost the most it can be raised to
	// (https://docs.aws.amazon.com/vpc/latest/userguide/amazon-vpc-limits.html).
	vpcBlockQuota = 5
	vpcBlockMost  = 50
)

var (
	vpcTen      = netip.MustParsePrefix("10.0.0.0/8")
	vpcTenLow   = netip.MustParsePrefix("10.0.0.0/15")
	vpcTenFirst = netip.MustParsePrefix("10.0.0.0/16")
	vpc172      = netip.MustParsePrefix("172.16.0.0/12")
	vpc172Last  = netip.MustParsePrefix("172.31.0.0/16")
	vpc192      = netip.MustParsePrefix("192.168.0.0/16")
	vpc198      = netip.MustParsePrefix("198.19.0.0/16")
	// vpcNever are ranges no VPC takes.
	vpcNever = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/4")}
)

// vpcFamily is the row of AWS's table a block falls in: one of the three
// private ranges, 198.19.0.0/16, or "public" for the rest (100.64.0.0/10
// with it, as the table puts them).
func vpcFamily(p netip.Prefix) string {
	for _, f := range []netip.Prefix{vpcTen, vpc172, vpc192, vpc198} {
		if f.Contains(p.Addr()) {
			return f.String()
		}
	}
	return "public"
}

// vpcBlocks is the VPC's blocks for a network's ranges, the one it is
// created with first. It returns why when AWS takes no VPC of them.
func vpcBlocks(ranges []netip.Prefix) ([]netip.Prefix, string) {
	var blocks []netip.Prefix
	for _, r := range ranges {
		r = r.Masked()
		for _, n := range vpcNever {
			if n.Overlaps(r) {
				return nil, fmt.Sprintf("its range %s is in %s, which no VPC takes", r, n)
			}
		}
		switch {
		case r.Bits() > minRange:
			return nil, fmt.Sprintf("its range %s is narrower than a VPC block (/%d to /%d)", r, maxVPC, minRange)
		case r.Bits() >= maxVPC:
			blocks = append(blocks, r)
		case maxVPC-r.Bits() > 6: // more than 64 /16s
			return nil, fmt.Sprintf("its range %s is more than %d blocks of /%d, the most a VPC can be given", r, vpcBlockMost, maxVPC)
		default:
			a := r.Addr()
			for i := 0; i < 1<<(maxVPC-r.Bits()); i++ {
				b := netip.PrefixFrom(a, maxVPC)
				blocks = append(blocks, b)
				four := a.As4()
				four[1]++
				a = netip.AddrFrom4(four)
			}
		}
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].Addr().Less(blocks[j].Addr()) })
	for i := 1; i < len(blocks); i++ {
		if blocks[i-1].Overlaps(blocks[i]) {
			return nil, fmt.Sprintf("its ranges %s and %s overlap", blocks[i-1], blocks[i])
		}
	}
	if len(blocks) > vpcBlockMost {
		return nil, fmt.Sprintf("its ranges are %d blocks; a VPC takes %d at most", len(blocks), vpcBlockMost)
	}
	// One private range only, and never with 198.19.0.0/16.
	fams := map[string]bool{}
	for _, b := range blocks {
		fams[vpcFamily(b)] = true
	}
	private := 0
	for _, f := range []netip.Prefix{vpcTen, vpc172, vpc192} {
		if fams[f.String()] {
			private++
		}
	}
	if private > 1 {
		return nil, "its ranges are in more than one of 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16; a VPC takes blocks of one of them only"
	}
	if fams[vpc198.String()] && private > 0 {
		return nil, "its ranges are in 198.19.0.0/16 and a private range; a VPC takes no block of both"
	}
	// Blocks AWS adds to no VPC, so each can only be the one a VPC is
	// created with: any in 10.0.0.0/16 beside one in 10.0.0.0/15, any in
	// 172.31.0.0/16, any in 198.19.0.0/16.
	var first []netip.Prefix
	for _, b := range blocks {
		switch {
		case vpcTenFirst.Contains(b.Addr()), vpc172Last.Contains(b.Addr()), vpc198.Contains(b.Addr()):
			first = append(first, b)
		}
	}
	if len(first) > 1 {
		var s []string
		for _, b := range first {
			s = append(s, b.String())
		}
		return nil, fmt.Sprintf("its ranges %s can each only be the block a VPC is created with (AWS adds no block of 10.0.0.0/16 beside one of 10.0.0.0/15, none of 172.31.0.0/16 and none of 198.19.0.0/16), and a VPC is created with one", strings.Join(s, " and "))
	}
	// The first block: the one that must be, or a private one (a private
	// block is added to no VPC created with a public one), or the lowest.
	lead := 0
	switch {
	case len(first) == 1:
		for i, b := range blocks {
			if b == first[0] {
				lead = i
			}
		}
	case private == 1:
		for i, b := range blocks {
			if f := vpcFamily(b); f != "public" {
				lead = i
				break
			}
		}
	}
	out := append([]netip.Prefix{blocks[lead]}, blocks[:lead]...)
	return append(out, blocks[lead+1:]...), ""
}

// vpcBlockOf is the block that holds a subnet's whole range.
func vpcBlockOf(blocks []netip.Prefix, sub netip.Prefix) (netip.Prefix, bool) {
	for _, b := range blocks {
		if b.Bits() <= sub.Bits() && b.Contains(sub.Addr()) {
			return b, true
		}
	}
	return netip.Prefix{}, false
}
