// Package specconv implements conversion of specifications to libcontainer
// configurations
package specconv

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const wildcard = -1

var allowedDevices = []*configs.Device{
	//allow mknod for any device
	{
		Type:        'c',
		Major:       wildcard,
		Minor:       wildcard,
		Permissions: "m",
		Allow:       true,
	},
	{
		Type:        'b',
		Major:       wildcard,
		Minor:       wildcard,
		Permissions: "m",
		Allow:       true,
	},
	{
		Type:        'c',
		Path:        "/dev/null",
		Major:       1,
		Minor:       3,
		Permissions: "rwm",
		Allow:       true,
	},
	{
		Type:        'c',
		Path:        "/dev/random",
		Major:       1,
		Minor:       8,
		Permissions: "rwm",
		Allow:       true,
	},
	{
		Type:        'c',
		Path:        "/dev/full",
		Major:       1,
		Minor:       7,
		Permissions: "rwm",
		Allow:       true,
	},
	{
		Type:        'c',
		Path:        "/dev/tty",
		Major:       5,
		Minor:       0,
		Permissions: "rwm",
		Allow:       true,
	},
	{
		Type:        'c',
		Path:        "/dev/zero",
		Major:       1,
		Minor:       5,
		Permissions: "rwm",
		Allow:       true,
	},
	{
		Type:        'c',
		Path:        "/dev/urandom",
		Major:       1,
		Minor:       9,
		Permissions: "rwm",
		Allow:       true,
	},
	{
		Type:        'c',
		Path:        "/dev/console",
		Major:       5,
		Minor:       1,
		Permissions: "rwm",
		Allow:       true,
	},
	// /dev/pts/ - pts namespaces are "coming soon"
	{
		Path:        "",
		Type:        'c',
		Major:       136,
		Minor:       wildcard,
		Permissions: "rwm",
		Allow:       true,
	},
	{
		Path:        "",
		Type:        'c',
		Major:       5,
		Minor:       2,
		Permissions: "rwm",
		Allow:       true,
	},
	// tuntap
	{
		Path:        "",
		Type:        'c',
		Major:       10,
		Minor:       200,
		Permissions: "rwm",
		Allow:       true,
	},
}

type CreateOpts struct {
	NoPivotRoot  bool
	NoNewKeyring bool
	Spec         *specs.Spec
	Rootless     bool
}

// given specification and a cgroup name
func CreateLibcontainerConfig(opts *CreateOpts) (*configs.Config, error) {
	// runc's cwd will always be the bundle path
	rcwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	cwd, err := filepath.Abs(rcwd)
	if err != nil {
		return nil, err
	}
	spec := opts.Spec
	rootfsPath := spec.Root.Path
	if !filepath.IsAbs(rootfsPath) {
		rootfsPath = filepath.Join(cwd, rootfsPath)
	}
	labels := []string{}
	for k, v := range spec.Annotations {
		labels = append(labels, fmt.Sprintf("%s=%s", k, v))
	}
	config := &configs.Config{
		Rootfs:       rootfsPath,
		NoPivotRoot:  opts.NoPivotRoot,
		Readonlyfs:   spec.Root.Readonly,
		Hostname:     spec.Hostname,
		Labels:       append(labels, fmt.Sprintf("bundle=%s", cwd)),
		NoNewKeyring: opts.NoNewKeyring,
		Rootless:     opts.Rootless,
		Version:      specs.Version,
	}

	c, err := createCgroupConfig(opts)
	if err != nil {
		return nil, err
	}
	config.Cgroups = c
	return config, err
}

func createCgroupConfig(opts *CreateOpts) (*configs.Cgroup, error) {
	var spec = opts.Spec

	c := &configs.Cgroup{
		Resources: &configs.Resources{},
	}

	r := spec.Linux.Resources
	if r == nil {
		return c, nil
	}
	for i, d := range spec.Linux.Resources.Devices {
		var (
			t     = "a"
			major = int64(-1)
			minor = int64(-1)
		)
		if d.Type != "" {
			t = d.Type
		}
		if d.Major != nil {
			major = *d.Major
		}
		if d.Minor != nil {
			minor = *d.Minor
		}
		if d.Access == "" {
			return nil, fmt.Errorf("device access at %d field cannot be empty", i)
		}
		dt, err := stringToCgroupDeviceRune(t)
		if err != nil {
			return nil, err
		}
		dd := &configs.Device{
			Type:        dt,
			Major:       major,
			Minor:       minor,
			Permissions: d.Access,
			Allow:       d.Allow,
		}
		c.Resources.Devices = append(c.Resources.Devices, dd)
	}
	if !opts.Rootless {
		c.Resources.Devices = append(c.Resources.Devices, allowedDevices...)
	}
	if r.Memory != nil {
		if r.Memory.Limit != nil {
			c.Resources.Memory = *r.Memory.Limit
		}
		if r.Memory.Reservation != nil {
			c.Resources.MemoryReservation = *r.Memory.Reservation
		}
		if r.Memory.Swap != nil {
			c.Resources.MemorySwap = *r.Memory.Swap
		}
		if r.Memory.Kernel != nil {
			c.Resources.KernelMemory = *r.Memory.Kernel
		}
		if r.Memory.KernelTCP != nil {
			c.Resources.KernelMemoryTCP = *r.Memory.KernelTCP
		}
		if r.Memory.Swappiness != nil {
			c.Resources.MemorySwappiness = r.Memory.Swappiness
		}
	}
	if r.CPU != nil {
		if r.CPU.Shares != nil {
			c.Resources.CpuShares = *r.CPU.Shares
		}
		if r.CPU.Quota != nil {
			c.Resources.CpuQuota = *r.CPU.Quota
		}
		if r.CPU.Period != nil {
			c.Resources.CpuPeriod = *r.CPU.Period
		}
		if r.CPU.RealtimeRuntime != nil {
			c.Resources.CpuRtRuntime = *r.CPU.RealtimeRuntime
		}
		if r.CPU.RealtimePeriod != nil {
			c.Resources.CpuRtPeriod = *r.CPU.RealtimePeriod
		}
		if r.CPU.Cpus != "" {
			c.Resources.CpusetCpus = r.CPU.Cpus
		}
		if r.CPU.Mems != "" {
			c.Resources.CpusetMems = r.CPU.Mems
		}
	}
	if r.Pids != nil {
		c.Resources.PidsLimit = r.Pids.Limit
	}
	if r.BlockIO != nil {
		if r.BlockIO.Weight != nil {
			c.Resources.BlkioWeight = *r.BlockIO.Weight
		}
		if r.BlockIO.LeafWeight != nil {
			c.Resources.BlkioLeafWeight = *r.BlockIO.LeafWeight
		}
		if r.BlockIO.WeightDevice != nil {
			for _, wd := range r.BlockIO.WeightDevice {
				var weight, leafWeight uint16
				if wd.Weight != nil {
					weight = *wd.Weight
				}
				if wd.LeafWeight != nil {
					leafWeight = *wd.LeafWeight
				}
				weightDevice := configs.NewWeightDevice(wd.Major, wd.Minor, weight, leafWeight)
				c.Resources.BlkioWeightDevice = append(c.Resources.BlkioWeightDevice, weightDevice)
			}
		}
		if r.BlockIO.ThrottleReadBpsDevice != nil {
			for _, td := range r.BlockIO.ThrottleReadBpsDevice {
				rate := td.Rate
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleReadBpsDevice = append(c.Resources.BlkioThrottleReadBpsDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleWriteBpsDevice != nil {
			for _, td := range r.BlockIO.ThrottleWriteBpsDevice {
				rate := td.Rate
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleWriteBpsDevice = append(c.Resources.BlkioThrottleWriteBpsDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleReadIOPSDevice != nil {
			for _, td := range r.BlockIO.ThrottleReadIOPSDevice {
				rate := td.Rate
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleReadIOPSDevice = append(c.Resources.BlkioThrottleReadIOPSDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleWriteIOPSDevice != nil {
			for _, td := range r.BlockIO.ThrottleWriteIOPSDevice {
				rate := td.Rate
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleWriteIOPSDevice = append(c.Resources.BlkioThrottleWriteIOPSDevice, throttleDevice)
			}
		}
	}
	for _, l := range r.HugepageLimits {
		c.Resources.HugetlbLimit = append(c.Resources.HugetlbLimit, &configs.HugepageLimit{
			Pagesize: l.Pagesize,
			Limit:    l.Limit,
		})
	}
	if r.DisableOOMKiller != nil {
		c.Resources.OomKillDisable = *r.DisableOOMKiller
	}
	if r.Network != nil {
		if r.Network.ClassID != nil {
			c.Resources.NetClsClassid = *r.Network.ClassID
		}
		for _, m := range r.Network.Priorities {
			c.Resources.NetPrioIfpriomap = append(c.Resources.NetPrioIfpriomap, &configs.IfPrioMap{
				Interface: m.Name,
				Priority:  int64(m.Priority),
			})
		}
	}
	return c, nil
}

func stringToCgroupDeviceRune(s string) (rune, error) {
	switch s {
	case "a":
		return 'a', nil
	case "b":
		return 'b', nil
	case "c":
		return 'c', nil
	default:
		return 0, fmt.Errorf("invalid cgroup device type %q", s)
	}
}
