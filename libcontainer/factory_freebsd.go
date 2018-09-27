package libcontainer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/opencontainers/runc/libcontainer/cgroups/rctl"
	"github.com/opencontainers/runc/libcontainer/configs"
)

const (
	stateFilename         = "state.json"
	execFifoFilename      = "exec.fifo"
	launchTmStampFilename = "launch.timestamp"
	initCmdPidFilename    = "init.pid"
)

type FreeBSDFactory struct {
	// Root directory for the factory to store state.
	Root string
}

func New(root string, options ...func(*FreeBSDFactory) error) (Factory, error) {
	if root != "" {
		if err := os.MkdirAll(root, 0700); err != nil {
			return nil, newGenericError(err, SystemError)
		}
	}

	l := &FreeBSDFactory{
		Root: root,
	}

	return l, nil
}

func (l *FreeBSDFactory) Create(id string, config *configs.Config) (Container, error) {
	if l.Root == "" {
		return nil, newGenericError(fmt.Errorf("invalid root"), ConfigInvalid)
	}

	uid, err := config.HostRootUID()
	if err != nil {
		return nil, newGenericError(err, SystemError)
	}
	gid, err := config.HostRootGID()
	if err != nil {
		return nil, newGenericError(err, SystemError)
	}
	containerRoot := filepath.Join(l.Root, id)
	if _, err := os.Stat(containerRoot); err == nil {
		return nil, newGenericError(fmt.Errorf("container with id exists: %v", id), IdInUse)
	} else if !os.IsNotExist(err) {
		return nil, newGenericError(err, SystemError)
	}
	if err := os.MkdirAll(containerRoot, 0711); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	if err := os.Chown(containerRoot, uid, gid); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	c := &freebsdContainer{
		id:     id,
		root:   containerRoot,
		config: config,
		cgroupManager: &rctl.Manager{
			Cgroups: config.Cgroups,
			Paths:   nil,
			Name: id,
		},
	}

	c.state = &stoppedState{c: c}
	return c, nil
}

func (l *FreeBSDFactory) Load(id string) (Container, error) {
	if l.Root == "" {
		return nil, newGenericError(fmt.Errorf("invalid root"), ConfigInvalid)
	}
	containerRoot := filepath.Join(l.Root, id)
	state, err := l.loadState(containerRoot, id)
	if err != nil {
		return nil, err
	}
	c := &freebsdContainer{
		initProcessPid:       state.InitProcessPid,
		initProcessStartTime: state.InitProcessStartTime,
		id:                   id,
		jailId:               state.JailId,
		devPartition:         state.DevPart,
		config:               &state.Config,
		root:                 containerRoot,
		created:              state.Created,
	}
	c.state = &loadedState{c: c}
	if err := c.refreshState(); err != nil {
		return nil, err
	}
	return c, nil
}

func (l *FreeBSDFactory) Type() string {
	return "libcontainer"
}

// StartInitialization loads a container by opening the pipe fd from the parent to read the configuration and state
// This is a low level implementation detail of the reexec and should not be consumed externally
func (l *FreeBSDFactory) StartInitialization() (err error) {
	// unsupported: it does not make any sense on FreeBSD because of FreeBSD Jail
	return nil
}

func (l *FreeBSDFactory) loadState(root, id string) (*State, error) {
	f, err := os.Open(filepath.Join(root, stateFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, newGenericError(fmt.Errorf("container %q does not exist", id), ContainerNotExists)
		}
		return nil, newGenericError(err, SystemError)
	}
	defer f.Close()
	var state *State
	if err := json.NewDecoder(f).Decode(&state); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	return state, nil
}
