// +build freebsd

package libcontainer

import (
	"fmt"
	
	"github.com/opencontainers/runc/libcontainer/configs"
//	"github.com/vishvananda/netlink"
)

var strategies = map[string]networkStrategy{
	"veth": &veth{},
	"loopback": &loopback{},
}

type networkStrategy interface {
	create(*network, int) error
	initialize(*network) error
	detach(*configs.Network) error
	attach(*configs.Network) error
}

func getStrategy(tpe string) (networkStrategy, error) {
	s, exists := strategies[tpe]
	if !exists {
		return nil, fmt.Errorf("unknownstrategy type %q", tpe)
	}
	return s, nil
}

type loopback struct {
}

func (l *loopback) create(n *network, nspid int) error {
	return nil
}

func (l *loopback) initialize(config *network) error {
//	return netlink.LinkSetUp(&netlink.Device{LinaAttrs: netlink.LinkAttrs{Name: "lo"}})
return nil
}

func (l *loopback) attach(n *configs.Network) (err error) {
	return nil
}

func (l *loopback) detach(n *configs.Network) (err error) {
	return nil
}

type veth struct {
}

func (v *veth) detach(n *configs.Network) (err error) {
//	return netlink.LinkSetMaster(&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: n.HostInterfaceName}}, nil)
 return nil
}

func (v *veth) attach(n *configs.Network) (err error) {
	return nil
}

func (v *veth) create(n *network, nspid int) (err error) {
	return nil
}

func (v *veth) initialize(config *network) error {
	return nil
}
