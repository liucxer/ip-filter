package ip_filter_test

import (
	"github.com/davecgh/go-spew/spew"
	ip_filter "github.com/liucxer/ip-filter"
	"github.com/stretchr/testify/require"
	"inet.af/netaddr"
	"net"
	"testing"
)

func TestFilter_AllowAccess(t *testing.T) {
	ip, err :=netaddr.ParseIP("1.0.1.0")
	require.NoError(t, err)

	mask, err :=netaddr.ParseIP("255.255.255.0")
	require.NoError(t, err)
	ipNet := &net.IPNet{
		IP:   ip.IPAddr().IP,
		Mask: net.IPMask(mask.IPAddr().IP),
	}

	ipPrefix, ok := netaddr.FromStdIPNet(ipNet)
	require.Equal(t, ok, true)
	spew.Dump(ipPrefix)
}

func TestIPFilter_AllowAccess(t *testing.T) {
	ipFilter, err := ip_filter.NewIpFilter().WithDenyChina()
	require.NoError(t, err)

	res, err := ipFilter.AllowAccess("222.209.99.196")
	spew.Dump(res)
}