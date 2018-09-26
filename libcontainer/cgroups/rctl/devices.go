// +build freebsd

package rctl

import (
	"fmt"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/system"
)

type DevicesGroup struct {
}

func (s *DevicesGroup) Name() string {
	return "devices"
}

func (s *DevicesGroup) Apply(d *cgroupData) error {
	_, err := d.join("devices")
	if err != nil {
		// We will return error even it's `not found` error, devices
		// cgroup is hard requirement for container's security.
		return err
	}
	return nil
}

func (s *DevicesGroup) Set(path string, cgroup *configs.Cgroup) error {
	if system.RunningInUserNS() {
		return nil
	}

	devices := cgroup.Resources.Devices
	if len(devices) > 0 {
		for _, dev := range devices {
			file := "devices.deny"
			if dev.Allow {
				file = "devices.allow"
			}
			fmt.Printf("%s %s\n", file, dev.CgroupString())
		/*
			if err := writeFile(path, file, dev.CgroupString()); err != nil {
				return err
			}
		*/
		}
		return nil
	}
	if cgroup.Resources.AllowAllDevices != nil {
		if *cgroup.Resources.AllowAllDevices == false {
			fmt.Printf("devices.deny a\n")
			/*
			if err := writeFile(path, "devices.deny", "a"); err != nil {
				return err
			}
			*/

			for _, dev := range cgroup.Resources.AllowedDevices {
				fmt.Printf("devices.allow %s\n", dev.CgroupString())
				/*
				if err := writeFile(path, "devices.allow", dev.CgroupString()); err != nil {
					return err
				}
				*/
			}
			return nil
		}

		fmt.Printf("devices.allow a\n")
	/*
		if err := writeFile(path, "devices.allow", "a"); err != nil {
			return err
		}
	*/
	}

	for _, dev := range cgroup.Resources.DeniedDevices {
		fmt.Printf("devices.deny %s\n", dev.CgroupString())
	/*
		if err := writeFile(path, "devices.deny", dev.CgroupString()); err != nil {
			return err
		}
	*/
	}

	return nil
}

func (s *DevicesGroup) Remove(d *cgroupData) error {
	return removePath(d.path("devices"))
}

func (s *DevicesGroup) GetStats(path string, stats *cgroups.Stats) error {
	return nil
}
