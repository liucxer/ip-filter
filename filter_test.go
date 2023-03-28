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
	ip, err := netaddr.ParseIP("1.0.1.0")
	require.NoError(t, err)

	mask, err := netaddr.ParseIP("255.255.255.0")
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

	ipFilter, err = ip_filter.NewIpFilter().WithDenyChina()
	require.NoError(t, err)

	res, err = ipFilter.AllowAccess("222.209.99.196")
	spew.Dump(res)
}

func TestIPFilter_DenyChinaAndTaiwan(t *testing.T) {
	ipFilter, err := ip_filter.NewIpFilter().WithDenyChina()
	require.NoError(t, err)

	res, err := ipFilter.WithDenyTaiwan()
	require.NoError(t, err)
	spew.Dump(res)

	res, err = ipFilter.WithDenyRussia()
	require.NoError(t, err)
	spew.Dump(res)

	// 测试中国
	resBool, err := ipFilter.AllowAccess("222.209.98.76")
	require.NoError(t, err)
	spew.Dump(resBool)
	require.Equal(t, resBool, false)

	// 测试台湾
	resBool, err = ipFilter.AllowAccess("1.168.0.1")
	require.NoError(t, err)
	spew.Dump(resBool)
	require.Equal(t, resBool, false)

	// 测试俄罗斯
	resBool, err = ipFilter.AllowAccess("217.199.224.1")
	require.NoError(t, err)
	spew.Dump(resBool)
	require.Equal(t, resBool, false)

	// 测试美国
	resBool, err = ipFilter.AllowAccess("2.17.192.1")
	require.NoError(t, err)
	require.Equal(t, resBool, true)
}
