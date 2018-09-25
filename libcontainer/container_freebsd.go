package libcontainer

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/utils"
)

type freebsdContainer struct {
	id                   string
	root                 string
	config               *configs.Config
	jailId               string
	initProcessPid       int
	initProcessStartTime uint64
	devPartition         string
	m                    sync.Mutex
	state                containerState
	created              time.Time
}

// State represents a running container's state
type State struct {
	BaseState

	JailId string `json:"jailid"`
	// Platform specific fields below here
	DevPart string `json:"devpart"`
	// Specifies if the container was started under the rootless mode.
	Rootless bool `json:"rootless"`
}

// A libcontainer container object.
//
// Each container is thread-safe within the same process. Since a container can
// be destroyed by a separate process, any function may return that the container
// was not found.
type Container interface {
	BaseContainer

	// Methods below here are platform specific

	// Execute a quick cmd in jail.
	// The cmd should finish in a short period (5s), and output
	// will be returned if no error occurs
	ExecInContainer(name string, args ...string) (string, error)
}

func (c *freebsdContainer) ID() string {
	return c.id
}

func (c *freebsdContainer) Status() (Status, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentStatus()
}

func (c *freebsdContainer) State() (*State, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentState()
}

func (c *freebsdContainer) Config() configs.Config {
	return *c.config
}

func (c *freebsdContainer) Processes() ([]int, error) {
	var pids []int
	cmd := exec.Command("/bin/ps", "ax", "-o", "jid,pid")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		fields := strings.Fields(line)
		if fields[0] == c.jailId {
			pid, err := strconv.Atoi(fields[1])
			if err != nil {
				return nil, fmt.Errorf("unexpected pid '%s': %s", fields[1], err)
			}
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func (c *freebsdContainer) Stats() (*Stats, error) {
	return nil, nil
}

func (c *freebsdContainer) Set(config configs.Config) error {
	return nil
}

func (c *freebsdContainer) ExecInContainer(name string, args ...string) (string, error) {
	if !c.isJailExisted(c.id, c.jailId) {
		return "", fmt.Errorf("container %s with jail Id %s has been removed", c.id, c.jailId)
	}
	argsNew := make([]string, 2+len(args))
	argsNew[0] = c.jailId
	argsNew[1] = name
	for i := 0; i < len(args); i++ {
		argsNew[i+2] = args[i]
	}
	out, err := c.runWrapper("/usr/sbin/jexec", argsNew...)
	if err != nil {
		return "", err
	}
	return out, nil
}

func (c *freebsdContainer) markCreated() (err error) {
	c.created = time.Now().UTC()
	c.state = &createdState{
		c: c,
	}
	state, err := c.updateState()
	if err != nil {
		return err
	}
	// init process start time may be "" if init has not finished
	c.initProcessStartTime = state.InitProcessStartTime
	return nil
}

func (c *freebsdContainer) markRunning() (err error) {
	c.jailId = c.getJailId(c.id)
	pid, _ := c.getInitProcessPid(c.jailId)
	pidInt, _ := strconv.Atoi(pid)
	c.initProcessPid = pidInt

	c.state = &runningState{
		c: c,
	}
	if _, err := c.updateState(); err != nil {
		return err
	}
	return nil
}

func (c *freebsdContainer) Start(process *Process) (err error) {
	c.m.Lock()
	defer c.m.Unlock()
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	if err := c.start(process, status == Stopped); err != nil {
		if status == Stopped {
			c.deleteExecFifo()
		}
		return err
	}
	return nil
}

func (c *freebsdContainer) getJailId(jname string) string {
	out, err := c.runWrapper("/usr/sbin/jls", "jid", "name")
	if err != nil {
		return ""
	}
	result := strings.Split(out, "\n")
	for i := range result {
		if len(result[i]) > 0 {
			line := strings.Split(result[i], " ")
			if line[1] == jname {
				return line[0]
			}
		}
	}
	return ""
}

func (c *freebsdContainer) isJailExisted(jname, jid string) bool {
	jid1 := c.getJailId(jname)
	if jid != "" && jid == jid1 {
		return true
	}
	return false
}

func (c *freebsdContainer) getInitProcessPid(jid string) (string, error) {
	if !c.isJailExisted(c.id, jid) {
		return "", fmt.Errorf("jail %s was destroyed", c.id)
	}
	out, err := c.runWrapper("/usr/sbin/jexec", jid, "/bin/cat", filepath.Join("/", initCmdPidFilename))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func (c *freebsdContainer) isInitProcessRunning(jid string) (bool, error) {
	pid, err := c.getInitProcessPid(jid)
	if err != nil {
		return false, err
	}
	if _, err := c.runWrapper("/usr/sbin/jexec", jid, "/bin/ps", "-p", pid); err != nil {
		return false, nil
	}
	return true, nil
}

func (c *freebsdContainer) getInitProcessTime(jid string) (int, error) {
	pid, err := c.getInitProcessPid(jid)
	if err != nil {
		return 0, err
	}
	isRunning, err := c.isInitProcessRunning(jid)
	if err != nil {
		return 0, err
	}
	if !isRunning {
		return 0, fmt.Errorf("init process does not exist")
	}
	out, err := c.runWrapper("/usr/sbin/jexec", jid, "/bin/ps", "-o", "etimes", pid)
	// The output should be like:
	// ELAPSED
	// 1874063
	if err != nil {
		return 0, err
	}
	s := strings.Split(out, "\n")
	elapsedSec, err := strconv.Atoi(s[1])
	return elapsedSec, nil
}

func (c *freebsdContainer) jailCmdTmpl(p *Process) (*exec.Cmd, error) {
	var (
		preCmdBuf  bytes.Buffer
		cmdBuf     bytes.Buffer
		conf       string
		jailStart  string
		jailStop   string
		devRelPath string
		devAbsPath string
	)
	preCmdBuf.WriteString(fmt.Sprintf("echo $$ > /%s; /bin/echo 0 > /%s",
		initCmdPidFilename, execFifoFilename))
	for _, v := range p.Args {
		if cmdBuf.Len() > 0 {
			cmdBuf.WriteString(" ")
		}
		cmdBuf.WriteString(v)
	}
	jailStart = fmt.Sprintf("/bin/sh /etc/rc")
	jailStop = fmt.Sprintf("/bin/sh /etc/rc.shutdown")
	params := map[string]string{
		"exec.clean":    "true",
		"exec.start":    jailStart,
		"exec.stop":     jailStop,
		"host.hostname": c.id,
		"path":          c.config.Rootfs,
		"command":       fmt.Sprintf("%s ; %s", preCmdBuf.String(), cmdBuf.String()),
	}
	devRelPath = filepath.Join(c.config.Rootfs, "dev")
	if devDir, err := os.Stat(devRelPath); err == nil {
		if devDir.IsDir() {
			devAbsPath, _ = filepath.Abs(devRelPath)
			params["mount.devfs"] = "true"
			c.devPartition = devAbsPath
		}
	}
	lines := make([]string, 0, len(params))
	for k, v := range params {
		lines = append(lines, fmt.Sprintf("	%v=%#v;", k, v))
	}
	sort.Strings(lines)
	conf = fmt.Sprintf("%v {\n%v\n}\n", c.id, strings.Join(lines, "\n"))
	jailConfPath := filepath.Join(c.root, "jail.conf")
	if _, err := os.Stat(jailConfPath); err == nil {
		os.Remove(jailConfPath)
	}
	if err := ioutil.WriteFile(jailConfPath, []byte(conf), 0400); err != nil {
		fmt.Println("Fail to create jail conf %s", jailConfPath)
		return nil, err
	}
	jidPath := filepath.Join(c.root, "jid")

	cmd := exec.Command("/usr/sbin/jail", "-J", jidPath, "-f", jailConfPath, "-c")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

func (c *freebsdContainer) launchJail(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	return c.markCreated()
}

func (c *freebsdContainer) cmdTmplInExistingJail(p *Process) (*exec.Cmd, error) {
	var (
		params  []string
		argsBuf bytes.Buffer
	)
	if !c.isJailExisted(c.id, c.jailId) {
		return nil, fmt.Errorf("jail %s was destroyed", c.id)
	}
	params = append(params, c.jailId)
	params = append(params, "/bin/sh")
	params = append(params, "-c")
	if p.Cwd != "" {
		argsBuf.WriteString("cd ")
		argsBuf.WriteString(p.Cwd)
		argsBuf.WriteString(";")
	}

	for _, v := range p.Args {
		argsBuf.WriteString(" ")
		argsBuf.WriteString(v)
	}
	params = append(params, argsBuf.String())
	cmd := exec.Command("/usr/sbin/jexec", params...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

func (c *freebsdContainer) start(process *Process, isInit bool) error {
	if isInit {
		cmd, err := c.jailCmdTmpl(process)
		if err != nil {
			return err
		}
		initProcess := c.newInitProcess(process, cmd)
		initProcess.start()
		return c.launchJail(cmd)
	} else {
		cmd, err := c.cmdTmplInExistingJail(process)
		if err != nil {
			return err
		}
		initProcess := &initProcess{
			cmd:       cmd,
			container: c,
			process:   process,
		}
		initProcess.start()
		return cmd.Start()
	}
}

func (c *freebsdContainer) Run(process *Process) (err error) {
	c.m.Lock()
	status, err := c.currentStatus()
	if err != nil {
		c.m.Unlock()
		return err
	}
	c.m.Unlock()
	var containerReady = make(chan bool)
	if status == Stopped {
		if err := c.createExecFifo(); err != nil {
			return err
		}
		go func() {
			c.exec()
			containerReady <- true
		}()
	}
	errs := c.Start(process)
	if status == Stopped {
		<-containerReady
	}
	if errs != nil {
		return errs
	}
	return nil
}

// execute the command in jail and wait for completion.
// the timeout is 5 seconds
func (c *freebsdContainer) runWrapper(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("execution time out: ", ctx.Err())
	}
	return string(output), nil
}

func (c *freebsdContainer) Destroy() error {
	c.m.Lock()
	defer c.m.Unlock()
	existJid := c.getJailId(c.id)
	if c.jailId != "" && existJid == c.jailId {
		if _, err := c.runWrapper("/usr/sbin/jail", "-r", c.jailId); err != nil {
			return fmt.Errorf("Fail to stop jail")
		}
		if c.devPartition != "" {
			if _, err := c.runWrapper("/sbin/umount", c.devPartition); err != nil {
				return fmt.Errorf("Fail to umount %s", c.devPartition)
			}
		}
		c.jailId = ""
	} else {
		fmt.Errorf("container %s has already been destroyed", c.id)
	}
	return c.state.destroy()
}

func (c *freebsdContainer) Signal(s os.Signal, all bool) error {
	existJid := c.getJailId(c.id)
	if c.jailId != "" && existJid == c.jailId {
		if all {
			if _, err := c.runWrapper("/usr/sbin/jexec", c.jailId, "/bin/kill", "-KILL", "-1"); err != nil {
				return fmt.Errorf("Fail to kill all processes")
			}
			// remove the configuration if the jail was destroyed
			j := c.getJailId(c.id)
			if j == "" {
				c.jailId = ""
				return c.state.destroy()
			}
		} else {
			initPid := strconv.Itoa(c.initProcessPid)
			if _, err := c.runWrapper("/usr/sbin/jexec", c.jailId, "/bin/kill", "-KILL", initPid); err != nil {
				return fmt.Errorf("Fail to kill all processes")
			}
		}
	} else {
		return fmt.Errorf("container %s has already been destroyed", c.id)
	}
	return nil
}

func (c *freebsdContainer) createExecFifo() error {
	rootuid, err := c.Config().HostRootUID()
	if err != nil {
		return err
	}
	rootgid, err := c.Config().HostRootGID()
	if err != nil {
		return err
	}

	fifoName := filepath.Join(c.config.Rootfs, execFifoFilename)
	if _, err := os.Stat(fifoName); err == nil {
		c.deleteExecFifo()
	}
	oldMask := syscall.Umask(0000)
	if err := syscall.Mkfifo(fifoName, 0622); err != nil {
		syscall.Umask(oldMask)
		return err
	}
	syscall.Umask(oldMask)
	if err := os.Chown(fifoName, rootuid, rootgid); err != nil {
		return err
	}
	return nil
}

func (c *freebsdContainer) deleteExecFifo() {
	fifoName := filepath.Join(c.config.Rootfs, execFifoFilename)
	os.Remove(fifoName)
}

func (c *freebsdContainer) Exec() error {
	c.m.Lock()
	defer c.m.Unlock()
	return c.exec()
}

func (c *freebsdContainer) exec() error {
	path := filepath.Join(c.config.Rootfs, execFifoFilename)
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return newSystemErrorWithCause(err, "open exec fifo for reading")
	}
	defer f.Close()
	// hold here util container writes something to the pipe,
	// which indicates the container is ready
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}
	if len(data) > 0 {
		c.markRunning()
		os.Remove(path)
		return nil
	}
	return fmt.Errorf("cannot start an already running container")
}

// doesInitProcessExist checks if the init process is still the same process
// as the initial one, it could happen that the original process has exited
// and a new process has been created with the same pid, in this case, the
// container would already be stopped.
func (c *freebsdContainer) doesInitProcessExist() (bool, error) {
	isRunning, err := c.isInitProcessRunning(c.jailId)
	if !isRunning {
		return false, nil
	}
	elapsedSec, err := c.getInitProcessTime(c.jailId)
	if err != nil {
		return false, newSystemErrorWithCause(err, "getting container start time")
	}
	if c.initProcessStartTime != uint64(elapsedSec) {
		return false, nil
	}
	return true, nil
}

func (c *freebsdContainer) runType() (Status, error) {
	if c.jailId == "" || !c.isJailExisted(c.id, c.jailId) {
		return Stopped, nil
	}
	// check if the process is still the original init process.
	exist, err := c.doesInitProcessExist()
	if !exist || err != nil {
		return Stopped, err
	}
	// We'll create exec fifo and blocking on it after container is created,
	// and delete it after start container.
	if _, err := os.Stat(filepath.Join(c.config.Rootfs, execFifoFilename)); err == nil {
		return Created, nil
	}
	return Running, nil
}

func (c *freebsdContainer) updateState() (*State, error) {
	state, err := c.currentState()
	if err != nil {
		return nil, err
	}
	err = c.saveState(state)
	if err != nil {
		return nil, err
	}
	return state, nil
}

func (c *freebsdContainer) saveState(s *State) error {
	f, err := os.Create(filepath.Join(c.root, stateFilename))
	if err != nil {
		return err
	}
	defer f.Close()
	return utils.WriteJSON(f, s)
}

func (c *freebsdContainer) deleteState() error {
	return os.Remove(filepath.Join(c.root, stateFilename))
}

func (c *freebsdContainer) isPaused() (bool, error) {
	// TODO
	return false, nil
}

func (c *freebsdContainer) currentState() (*State, error) {
	var (
		startTime uint64
		pidInt    int
	)
	if c.jailId != "" {
		pidInt = c.initProcessPid
		if pidInt == 0 {
			pid, _ := c.getInitProcessPid(c.jailId)
			pidInt, _ := strconv.Atoi(pid)
			c.initProcessPid = pidInt
		}
		if c.initProcessStartTime == 0 {
			elaspedTime, _ := c.getInitProcessTime(c.jailId)
			startTime = uint64(elaspedTime)
		} else {
			startTime = c.initProcessStartTime
		}
	}
	state := &State{
		BaseState: BaseState{
			ID:                   c.ID(),
			Config:               *c.config,
			InitProcessPid:       pidInt,
			InitProcessStartTime: startTime,
			Created:              c.created,
		},
		JailId:   c.jailId,
		DevPart:  c.devPartition,
		Rootless: c.config.Rootless,
	}
	return state, nil
}

func (c *freebsdContainer) currentStatus() (Status, error) {
	if err := c.refreshState(); err != nil {
		return -1, err
	}
	return c.state.status(), nil
}

// refreshState needs to be called to verify that the current state on the
// container is what is true.  Because consumers of libcontainer can use it
// out of process we need to verify the container's status based on runtime
// information and not rely on our in process info.
func (c *freebsdContainer) refreshState() error {
	paused, err := c.isPaused()
	if err != nil {
		return err
	}
	if paused {
		return c.state.transition(&pausedState{c: c})
	}
	t, err := c.runType()
	if err != nil {
		return err
	}
	switch t {
	case Created:
		return c.state.transition(&createdState{c: c})
	case Running:
		return c.state.transition(&runningState{c: c})
	}
	return c.state.transition(&stoppedState{c: c})
}

func (c *freebsdContainer) newInitProcess(p *Process, cmd *exec.Cmd) *initProcess {
	cmd.Env = append(cmd.Env, "_LIBCONTAINER_INITTYPE="+string(initStandard))
	return &initProcess{
		cmd:       cmd,
		container: c,
		config:    c.newInitConfig(p),
		process:   p,
	}
}

func (c *freebsdContainer) newInitConfig(process *Process) *initConfig {
	cfg := &initConfig{
		Config:  c.config,
		Rlimits: c.config.Rlimits,
	}
	if len(process.Rlimits) > 0 {
		cfg.Rlimits = process.Rlimits
	}

	return cfg
}
