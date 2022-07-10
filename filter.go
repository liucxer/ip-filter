package ip_filter

import (
	"encoding/xml"
	"inet.af/netaddr"
	"io/ioutil"
	"net"
	"net/http"
)

type IPFilter struct {
	Allow *netaddr.IPSet
	Deny  *netaddr.IPSet
}

func NewIpFilter() *IPFilter {
	ipFilter := &IPFilter{}
	return ipFilter
}

var CacheData = map[string][]byte{}

func (f *IPFilter) WithDenyChina() (*IPFilter, error) {
	var (
		bts []byte
		ok bool
		err error
	)
	denyChinaUrl :="https://raw.githubusercontent.com/liucxer/ip-filter/main/config/deny-china.xml"

	if bts, ok = CacheData[denyChinaUrl]; !ok {
		resp, err := http.Get(denyChinaUrl)
		if err != nil {
			return f, err
		}

		bts, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return f, err
		}
		CacheData[denyChinaUrl] = bts
	}


	filter, err := f.ParserByte(bts)
	if err != nil {
		return f, err
	}
	denyBuilder := netaddr.IPSetBuilder{}
	allowBuilder := netaddr.IPSetBuilder{}
	denyBuilder.AddSet(filter.Deny)
	allowBuilder.AddSet(filter.Allow)

	denyBuilder.AddSet(f.Deny)
	allowBuilder.AddSet(f.Allow)

	f.Deny, _ = denyBuilder.IPSet()
	f.Allow, _ = allowBuilder.IPSet()

	return f, err
}

type Firewall struct {
	XMLName         xml.Name `xml:"configuration"`
	SystemWebServer struct {
		Security struct {
			IpSecurity struct {
				AllowUnlisted string `xml:"allowUnlisted,attr"`
				Address       []struct {
					IpAddress  string `xml:"ipAddress,attr"`
					SubnetMask string `xml:"subnetMask,attr"`
				} `xml:"add"`
			} `xml:"ipSecurity"`
		} `xml:"security"`
	} `xml:"system.webServer"`
}

func (p *IPFilter) ParserByte(bts []byte) (*IPFilter, error) {
	var filter IPFilter
	var firewall Firewall
	err := xml.Unmarshal(bts, &firewall)
	if err != nil {
		return nil, err
	}
	addr := firewall.SystemWebServer.Security.IpSecurity.Address
	var b netaddr.IPSetBuilder
	for _, item := range addr {
		ip, err :=netaddr.ParseIP(item.IpAddress)
		if err != nil {
			return nil, err
		}

		mask, err :=netaddr.ParseIP(item.SubnetMask)
		if err != nil {
			return nil, err
		}

		ipNet := &net.IPNet{
			IP:   ip.IPAddr().IP,
			Mask: net.IPMask(mask.IPAddr().IP),
		}

		ipPrefix, ok := netaddr.FromStdIPNet(ipNet)
		if !ok {
			continue
		}
		b.AddPrefix(ipPrefix)
	}
	if firewall.SystemWebServer.Security.IpSecurity.AllowUnlisted == "true" {
		filter.Deny, _ = b.IPSet()
	} else {
		filter.Allow, _ = b.IPSet()
	}

	return &filter, nil
}


func (f *IPFilter) AllowAccess(ip string) (bool, error) {
	netAddrIP, err := netaddr.ParseIP(ip)
	if err != nil {
		return false, err
	}

	if f.Allow != nil {
		if f.Allow.Contains(netAddrIP) {
			return true, err
		}
	}

	if f.Deny != nil {
		if f.Deny.Contains(netAddrIP) {
			return false, err
		}
	}

	return true, nil
}