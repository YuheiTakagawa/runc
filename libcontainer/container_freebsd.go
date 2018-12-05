package libcontainer

import (
	"bytes"
	//"encoding/json"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

//	"golang.org/x/sys/unix"

	"github.com/Sirupsen/logrus"
	"github.com/golang/protobuf/proto"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/opencontainers/runc/libcontainer/criurpc"
)

type freebsdContainer struct {
	id                   string
	root                 string
	config               *configs.Config
	jailId               string
	initProcessPid       int
	initProcessStartTime uint64
	criuPath             string
	devPartition         string
	m                    sync.Mutex
	criuVersion          int
	state                containerState
	created              time.Time
	cgroupManager        cgroups.Manager
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

	Checkpoint(criuOpts *CriuOpts) error
	Restore(process *Process, criuOpts *CriuOpts) error
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
			config: c.newInitConfig(process),
		}
		initProcess.vvstart()
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
		/* For FreeBSD cpuset(1) and (2) target active jail. This timing is best.*/
		c.cgroupManager.Afterset(c.jailId, c.config)
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
		manager:   c.cgroupManager,
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

var criuFeatures *criurpc.CriuFeatures

func (c *freebsdContainer) checkCriuFeatures(criuOpts *CriuOpts, rpcOpts *criurpc.CriuOpts, criuFeat *criurpc.CriuFeatures) error {

	var t criurpc.CriuReqType
	t = criurpc.CriuReqType_FEATURE_CHECK

	if err := c.checkCriuVersion("1.8"); err != nil {
		// Feature checking was introduced with CRIU 1.8.
		// Ignore the feature check if an older CRIU version is used
		// and just act as before.
		// As all automated PR testing is done using CRIU 1.7 this
		// code will not be tested by automated PR testing.
		return nil
	}

	// make sure the features we are looking for are really not from
	// some previous check
	criuFeatures = nil

	req := &criurpc.CriuReq{
		Type: &t,
		// Theoretically this should not be necessary but CRIU
		// segfaults if Opts is empty.
		// Fixed in CRIU  2.12
		Opts:     rpcOpts,
		Features: criuFeat,
	}

	err := c.criuSwrkCheckpoint(nil, req, criuOpts, false)
	if err != nil {
		logrus.Debugf("%s", err)
		return fmt.Errorf("CRIU feature check failed")
	}

	logrus.Debugf("Feature check says: %s", criuFeatures)
	missingFeatures := false

	if *criuFeat.MemTrack && !*criuFeatures.MemTrack {
		missingFeatures = true
		logrus.Debugf("CRIU does not support MemTrack")
	}

	if missingFeatures {
		return fmt.Errorf("CRIU is missing features")
	}

	return nil
}

// checkCriuVersion checks Criu version greater than or equal to minVersion
func (c *freebsdContainer) checkCriuVersion(minVersion string) error {
	var x, y, z, versionReq int

	_, err := fmt.Sscanf(minVersion, "%d.%d.%d\n", &x, &y, &z) // 1.5.2
	if err != nil {
		_, err = fmt.Sscanf(minVersion, "Version: %d.%d\n", &x, &y) // 1.6
	}
	versionReq = x*10000 + y*100 + z

	out, err := exec.Command(c.criuPath, "-V").Output()
	if err != nil {
		return fmt.Errorf("Unable to execute CRIU command: %s", c.criuPath)
	}

	x = 0
	y = 0
	z = 0
	if ep := strings.Index(string(out), "-"); ep >= 0 {
		// criu Git version format
		var version string
		if sp := strings.Index(string(out), "GitID"); sp > 0 {
			version = string(out)[sp:ep]
		} else {
			return fmt.Errorf("Unable to parse the CRIU version: %s", c.criuPath)
		}

		n, err := fmt.Sscanf(string(version), "GitID: v%d.%d.%d", &x, &y, &z) // 1.5.2
		if err != nil {
			n, err = fmt.Sscanf(string(version), "GitID: v%d.%d", &x, &y) // 1.6
			y++
		} else {
			z++
		}
		if n < 2 || err != nil {
			return fmt.Errorf("Unable to parse the CRIU version: %s %d %s", version, n, err)
		}
	} else {
		// criu release version format
		n, err := fmt.Sscanf(string(out), "Version: %d.%d.%d\n", &x, &y, &z) // 1.5.2
		if err != nil {
			n, err = fmt.Sscanf(string(out), "Version: %d.%d\n", &x, &y) // 1.6
		}
		if n < 2 || err != nil {
			return fmt.Errorf("Unable to parse the CRIU version: %s %d %s", out, n, err)
		}
	}

	c.criuVersion = x*10000 + y*100 + z

	if c.criuVersion < versionReq {
		return fmt.Errorf("CRIU version %d must be %d or higher", c.criuVersion, versionReq)
	}

	return nil
}

const descriptorsFilename = "descriptors.json"

func (c *freebsdContainer) addCriuDumpMount(req *criurpc.CriuReq, m *configs.Mount) {
	mountDest := m.Destination
	if strings.HasPrefix(mountDest, c.config.Rootfs) {
		mountDest = mountDest[len(c.config.Rootfs):]
	}

	extMnt := &criurpc.ExtMountMap{
		Key: proto.String(mountDest),
		Val: proto.String(mountDest),
	}
	req.Opts.ExtMnt = append(req.Opts.ExtMnt, extMnt)
}

func (c *freebsdContainer) addMaskPaths(req *criurpc.CriuReq) error {
	for _, path := range c.config.MaskPaths {
		fi, err := os.Stat(fmt.Sprintf("/proc/%d/root/%s", c.initProcessPid, path))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if fi.IsDir() {
			continue
		}

		extMnt := &criurpc.ExtMountMap{
			Key: proto.String(path),
			Val: proto.String("/dev/null"),
		}
		req.Opts.ExtMnt = append(req.Opts.ExtMnt, extMnt)
	}

	return nil
}

func (c *freebsdContainer) Checkpoint(criuOpts *CriuOpts) error {
	c.m.Lock()

	// TODO(avagin): Figure out how to make this work nicely. CRIU 2.0 has
	//               support for doing unprivileged dumps, but the setup of
	//               rootless containers might make this complicated.
	if c.config.Rootless {
		return fmt.Errorf("cannot checkpoint a rootless container")
	}

	if err := c.checkCriuVersion("1.5.2"); err != nil {
		return err
	}

	if criuOpts.ImagesDirectory == "" {
		return fmt.Errorf("invalid directory to save checkpoint")
	}

	// Since a container can be C/R'ed multiple times,
	// the checkpoint directory may already exist.
	if err := os.Mkdir(criuOpts.ImagesDirectory, 0755); err != nil && !os.IsExist(err) {
		return err
	}

	if criuOpts.WorkDirectory == "" {
	//	criuOpts.WorkDirectory = filepath.Join(c.root, "criu.work")
		criuOpts.WorkDirectory = filepath.Join("/", "criu.work")
	}

	if err := os.Mkdir(criuOpts.WorkDirectory, 0755); err != nil && !os.IsExist(err) {
		return err
	}

	workDir, err := os.Open(criuOpts.WorkDirectory)
	if err != nil {
		return err
	}
	defer workDir.Close()

	imageDir, err := os.Open(criuOpts.ImagesDirectory)
	if err != nil {
		return err
	}
	defer imageDir.Close()

	rpcOpts := criurpc.CriuOpts{
		ImagesDirFd:     proto.Int32(int32(imageDir.Fd())),
		WorkDirFd:       proto.Int32(int32(workDir.Fd())),
		LogLevel:        proto.Int32(4),
		LogFile:         proto.String("dump.log"),
		Root:            proto.String(c.config.Rootfs),
		ManageCgroups:   proto.Bool(true),
		NotifyScripts:   proto.Bool(true),
		Pid:             proto.Int32(int32(c.initProcessPid)),
		ShellJob:        proto.Bool(criuOpts.ShellJob),
		LeaveRunning:    proto.Bool(criuOpts.LeaveRunning),
		TcpEstablished:  proto.Bool(criuOpts.TcpEstablished),
		ExtUnixSk:       proto.Bool(criuOpts.ExternalUnixConnections),
		FileLocks:       proto.Bool(criuOpts.FileLocks),
		EmptyNs:         proto.Uint32(criuOpts.EmptyNs),
		OrphanPtsMaster: proto.Bool(true),
	}

	// append optional criu opts, e.g., page-server and port
	if criuOpts.PageServer.Address != "" && criuOpts.PageServer.Port != 0 {
		rpcOpts.Ps = &criurpc.CriuPageServerInfo{
			Address: proto.String(criuOpts.PageServer.Address),
			Port:    proto.Int32(criuOpts.PageServer.Port),
		}
	}

	//pre-dump may need parentImage param to complete iterative migration
	if criuOpts.ParentImage != "" {
		rpcOpts.ParentImg = proto.String(criuOpts.ParentImage)
		rpcOpts.TrackMem = proto.Bool(true)
	}

	// append optional manage cgroups mode
	if criuOpts.ManageCgroupsMode != 0 {
		if err := c.checkCriuVersion("1.7"); err != nil {
			return err
		}
		mode := criurpc.CriuCgMode(criuOpts.ManageCgroupsMode)
		rpcOpts.ManageCgroupsMode = &mode
	}

	var t criurpc.CriuReqType
	if criuOpts.PreDump {
		feat := criurpc.CriuFeatures{
			MemTrack: proto.Bool(true),
		}

		if err := c.checkCriuFeatures(criuOpts, &rpcOpts, &feat); err != nil {
			return err
		}

		t = criurpc.CriuReqType_PRE_DUMP
	} else {
		t = criurpc.CriuReqType_DUMP
	}
	req := &criurpc.CriuReq{
		Type: &t,
		Opts: &rpcOpts,
	}

	c.m.Unlock()

	err = c.criuSwrkCheckpoint(nil, req, criuOpts, false)
	if err != nil {
		return err
	}
	return nil
}

func (c *freebsdContainer) addCriuRestoreMount(req *criurpc.CriuReq, m *configs.Mount) {
	mountDest := m.Destination
	if strings.HasPrefix(mountDest, c.config.Rootfs) {
		mountDest = mountDest[len(c.config.Rootfs):]
	}

	extMnt := &criurpc.ExtMountMap{
		Key: proto.String(mountDest),
		Val: proto.String(m.Source),
	}
	req.Opts.ExtMnt = append(req.Opts.ExtMnt, extMnt)
}

func (c *freebsdContainer) restoreNetwork(req *criurpc.CriuReq, criuOpts *CriuOpts) {
	for _, iface := range c.config.Networks {
		switch iface.Type {
		case "veth":
			veth := new(criurpc.CriuVethPair)
			veth.IfOut = proto.String(iface.HostInterfaceName)
			veth.IfIn = proto.String(iface.Name)
			req.Opts.Veths = append(req.Opts.Veths, veth)
			break
		case "loopback":
			break
		}
	}
	for _, i := range criuOpts.VethPairs {
		veth := new(criurpc.CriuVethPair)
		veth.IfOut = proto.String(i.HostInterfaceName)
		veth.IfIn = proto.String(i.ContainerInterfaceName)
		req.Opts.Veths = append(req.Opts.Veths, veth)
	}
}

func (c *freebsdContainer) Restore(process *Process, criuOpts *CriuOpts) error {
	c.m.Lock()
	// TODO(avagin): Figure out how to make this work nicely. CRIU doesn't have
	//               support for unprivileged restore at the moment.
	if c.config.Rootless {
		return fmt.Errorf("cannot restore a rootless container")
	}

	if err := c.checkCriuVersion("1.5.2"); err != nil {
		return err
	}
	if criuOpts.WorkDirectory == "" {
	//	criuOpts.WorkDirectory = filepath.Join(c.root, "criu.work")
		criuOpts.WorkDirectory = filepath.Join("/", "criu.work")
	}
	// Since a container can be C/R'ed multiple times,
	// the work directory may already exist.
	if err := os.Mkdir(criuOpts.WorkDirectory, 0655); err != nil && !os.IsExist(err) {
		return err
	}
	workDir, err := os.Open(criuOpts.WorkDirectory)
	if err != nil {
		return err
	}
	defer workDir.Close()
	if criuOpts.ImagesDirectory == "" {
		return fmt.Errorf("invalid directory to restore checkpoint")
	}
	imageDir, err := os.Open(criuOpts.ImagesDirectory)
	if err != nil {
		return err
	}
	defer imageDir.Close()
	// CRIU has a few requirements for a root directory:
	// * it must be a mount point
	// * its parent must not be overmounted
	// c.config.Rootfs is bind-mounted to a temporary directory
	// to satisfy these requirements.
	root := filepath.Join(c.root, "criu-root")
	if err := os.Mkdir(root, 0755); err != nil {
		return err
	}
	defer os.Remove(root)
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}

	t := criurpc.CriuReqType_RESTORE
	req := &criurpc.CriuReq{
		Type: &t,
		Opts: &criurpc.CriuOpts{
			ImagesDirFd:     proto.Int32(int32(imageDir.Fd())),
			WorkDirFd:       proto.Int32(int32(workDir.Fd())),
			EvasiveDevices:  proto.Bool(true),
			LogLevel:        proto.Int32(4),
			LogFile:         proto.String("restore.log"),
			RstSibling:      proto.Bool(true),
			Root:            proto.String(root),
			ManageCgroups:   proto.Bool(true),
			NotifyScripts:   proto.Bool(true),
			Pid:		 proto.Int32(int32(criuOpts.Pid)),
			ShellJob:        proto.Bool(criuOpts.ShellJob),
			ExtUnixSk:       proto.Bool(criuOpts.ExternalUnixConnections),
			TcpEstablished:  proto.Bool(criuOpts.TcpEstablished),
			FileLocks:       proto.Bool(criuOpts.FileLocks),
			EmptyNs:         proto.Uint32(criuOpts.EmptyNs),
			OrphanPtsMaster: proto.Bool(true),
		},
	}
	c.m.Unlock()

	ret := c.criuSwrkRestore(process, req, criuOpts, true)
	c.markRunning()
	c.state = &restoredState{
		imageDir: criuOpts.ImagesDirectory,
		c:	c,
	}
	return ret

}

func (c *freebsdContainer) criuApplyCgroups(pid int, req *criurpc.CriuReq) error {
	// XXX: Do we need to deal with this case? AFAIK criu still requires root.
	if err := c.cgroupManager.Apply(pid); err != nil {
		return err
	}

	if err := c.cgroupManager.Set(c.config); err != nil {
		return newSystemError(err)
	}

	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	cgroupsPaths, err := cgroups.ParseCgroupFile(path)
	if err != nil {
		return err
	}

	for c, p := range cgroupsPaths {
		cgroupRoot := &criurpc.CgroupRoot{
			Ctrl: proto.String(c),
			Path: proto.String(p),
		}
		req.Opts.CgRoot = append(req.Opts.CgRoot, cgroupRoot)
	}

	return nil
}

func (c *freebsdContainer) criuSwrkCheckpoint(process *Process, req *criurpc.CriuReq, opts *CriuOpts, applyCgroups bool) error {
	logPath := filepath.Join(opts.WorkDirectory, req.GetOpts().GetLogFile())

	path := "/criu-fifo"
	os.Remove(path)
	listener, err := net.Listen("unixpacket", path)
	if err != nil {
		fmt.Println(err)
	}
	defer listener.Close()

	args := []string{"swrk", "3"}
	logrus.Debugf("Using CRIU %d at: %s", c.criuVersion, c.criuPath)
	logrus.Debugf("Using CRIU with following args: %s", args)

	cmd := exec.Command("criu", args...)
	if process != nil {
		cmd.Stdin = process.Stdin
		cmd.Stdout = process.Stdout
		cmd.Stderr = process.Stderr
	}
	cmd.Stdout = os.Stdout
	//cmd.ExtraFiles = append(cmd.ExtraFiles, criuServer)

	if err:= cmd.Start(); err != nil {
		fmt.Println(err)
		return err
	}

	conn, err := listener.Accept()
	if err != nil {
		fmt.Println(err)
		return err
	}
	criuClientCon := conn.(*net.UnixConn)

	defer func() {
		criuClientCon.Close()
		_, err := cmd.Process.Wait()
		if err != nil {
			return
		}
	}()

/*
	if applyCgroups {
		err := c.criuApplyCgroups(cmd.Process.Pid, req)
		if err != nil {
			return err
		}
	}
	*/


	var extFds []string
	/*
	if process != nil {
		extFds, err = getPipeFds(cmd.Process.Pid)
		if err != nil {
			return err
		}
	}
*/
	logrus.Debugf("Using CRIU in %s mode", req.GetType().String())
	// In the case of criurpc.CriuReqType_FEATURE_CHECK req.GetOpts()
	// should be empty. For older CRIU versions it still will be
	// available but empty.
	if req.GetType() != criurpc.CriuReqType_FEATURE_CHECK {
		val := reflect.ValueOf(req.GetOpts())
		v := reflect.Indirect(val)
		for i := 0; i < v.NumField(); i++ {
			st := v.Type()
			name := st.Field(i).Name
			if strings.HasPrefix(name, "XXX_") {
				continue
			}
			value := val.MethodByName("Get" + name).Call([]reflect.Value{})
			logrus.Debugf("CRIU option %s with value %v", name, value[0])
		}
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	fmt.Println(len(data))
	_, err = criuClientCon.Write(data)
	if err != nil {
		return err
	}
	buf := make([]byte, 10*4096)
	oob := make([]byte, 4096)
	for true {
		n, oobn, _, _, err := criuClientCon.ReadMsgUnix(buf, oob)
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("unexpected EOF")
		}
		if n == len(buf) {
			return fmt.Errorf("buffer is too small")
		}

		resp := new(criurpc.CriuResp)
		err = proto.Unmarshal(buf[:n], resp)
		if err != nil {
			return err
		}
		if !resp.GetSuccess() {
			typeString := req.GetType().String()
			return fmt.Errorf("criu failed: type %s errno %d\nlog file: %s", typeString, resp.GetCrErrno(), logPath)
		}

		t := resp.GetType()
		switch {
		case t == criurpc.CriuReqType_FEATURE_CHECK:
			logrus.Debugf("Feature check says: %s", resp)
			criuFeatures = resp.GetFeatures()
			break
		case t == criurpc.CriuReqType_NOTIFY:
			if err := c.criuNotifications(resp, process, opts, extFds, oob[:oobn]); err != nil {
				return err
			}
			t = criurpc.CriuReqType_NOTIFY
			req = &criurpc.CriuReq{
				Type:          &t,
				NotifySuccess: proto.Bool(true),
			}
			data, err = proto.Marshal(req)
			if err != nil {
				return err
			}
			_, err = criuClientCon.Write(data)
			if err != nil {
				return err
			}
			continue
		case t == criurpc.CriuReqType_RESTORE:
		case t == criurpc.CriuReqType_DUMP:
		case t == criurpc.CriuReqType_PRE_DUMP:
		default:
			return fmt.Errorf("unable to parse the response %s", resp.String())
		}

		break
	}

	criuClientCon.CloseWrite()
	// cmd.Wait() waits cmd.goroutines which are used for proxying file descriptors.
	// Here we want to wait only the CRIU process.
	st, err := cmd.Process.Wait()
	if err != nil {
		return err
	}

	// In pre-dump mode CRIU is in a loop and waits for
	// the final DUMP command.
	// The current runc pre-dump approach, however, is
	// start criu in PRE_DUMP once for a single pre-dump
	// and not the whole series of pre-dump, pre-dump, ...m, dump
	// If we got the message CriuReqType_PRE_DUMP it means
	// CRIU was successful and we need to forcefully stop CRIU
	if !st.Success() && *req.Type != criurpc.CriuReqType_PRE_DUMP {
		return fmt.Errorf("criu failed: %s\nlog file: %s", st.String(), logPath)
	}
	return nil
}

// block any external network activity
func lockNetwork(config *configs.Config) error {
	for _, config := range config.Networks {
		strategy, err := getStrategy(config.Type)
		if err != nil {
			return err
		}

		if err := strategy.detach(config); err != nil {
			return err
		}
	}
	return nil
}

func (c *freebsdContainer) criuSwrkRestore(process *Process, req *criurpc.CriuReq, opts *CriuOpts, applyCgroups bool) error {
	logPath := filepath.Join(opts.WorkDirectory, req.GetOpts().GetLogFile())

	path := "/mycontainer/rootfs/criu-fifo"
	os.Remove(path)
	listener, err := net.Listen("unixpacket", path)
	if err != nil {
		fmt.Println(err)
	}
	defer listener.Close()

	args := []string{"/criu", "swrk", "3"}
	logrus.Debugf("Using CRIU %d at: %s", c.criuVersion, c.criuPath)
	logrus.Debugf("Using CRIU with following args: %s", args)
	c.m.Lock()
	c.currentStatus()
	process.Args = args
	cmd, err := c.jailCmdTmpl(process)
	if err != nil {
		return err
	}
	if process != nil {
		cmd.Stdin = process.Stdin
		cmd.Stdout = process.Stdout
		cmd.Stderr = process.Stderr
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	initProcess := c.newInitProcess(process, cmd)
	initProcess.start()

	err = c.launchJail(cmd)
	if err != nil {
		fmt.Println(err)
	}
	c.m.Unlock()

	conn, err := listener.Accept()
	if err != nil {
		fmt.Println(err)
		return err
	}
	criuClientCon := conn.(*net.UnixConn)

	defer func() {
		criuClientCon.Close()
		_, err := cmd.Process.Wait()
		if err != nil {
			return
		}
	}()

	var extFds []string

	logrus.Debugf("Using CRIU in %s mode", req.GetType().String())
	// In the case of criurpc.CriuReqType_FEATURE_CHECK req.GetOpts()
	// should be empty. For older CRIU versions it still will be
	// available but empty.
	if req.GetType() != criurpc.CriuReqType_FEATURE_CHECK {
		val := reflect.ValueOf(req.GetOpts())
		v := reflect.Indirect(val)
		for i := 0; i < v.NumField(); i++ {
			st := v.Type()
			name := st.Field(i).Name
			if strings.HasPrefix(name, "XXX_") {
				continue
			}
			value := val.MethodByName("Get" + name).Call([]reflect.Value{})
			logrus.Debugf("CRIU option %s with value %v", name, value[0])
		}
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	fmt.Println(len(data))
	_, err = criuClientCon.Write(data)
	if err != nil {
		return err
	}
	buf := make([]byte, 10*4096)
	oob := make([]byte, 4096)
	for true {
		n, oobn, _, _, err := criuClientCon.ReadMsgUnix(buf, oob)
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("unexpected EOF")
		}
		if n == len(buf) {
			return fmt.Errorf("buffer is too small")
		}

		resp := new(criurpc.CriuResp)
		err = proto.Unmarshal(buf[:n], resp)
		if err != nil {
			return err
		}
		if !resp.GetSuccess() {
			typeString := req.GetType().String()
			return fmt.Errorf("criu failed: type %s errno %d\nlog file: %s", typeString, resp.GetCrErrno(), logPath)
		}

		t := resp.GetType()
		switch {
		case t == criurpc.CriuReqType_FEATURE_CHECK:
			logrus.Debugf("Feature check says: %s", resp)
			criuFeatures = resp.GetFeatures()
			break
		case t == criurpc.CriuReqType_NOTIFY:
			if err := c.criuNotifications(resp, process, opts, extFds, oob[:oobn]); err != nil {
				return err
			}
			t = criurpc.CriuReqType_NOTIFY
			req = &criurpc.CriuReq{
				Type:          &t,
				NotifySuccess: proto.Bool(true),
			}
			data, err = proto.Marshal(req)
			if err != nil {
				return err
			}
			_, err = criuClientCon.Write(data)
			if err != nil {
				return err
			}
			continue
		case t == criurpc.CriuReqType_RESTORE:
		case t == criurpc.CriuReqType_DUMP:
		case t == criurpc.CriuReqType_PRE_DUMP:
		default:
			return fmt.Errorf("unable to parse the response %s", resp.String())
		}

		break
	}

	criuClientCon.CloseWrite()
	// cmd.Wait() waits cmd.goroutines which are used for proxying file descriptors.
	// Here we want to wait only the CRIU process.
	st, err := cmd.Process.Wait()
	if err != nil {
		return err
	}

	// In pre-dump mode CRIU is in a loop and waits for
	// the final DUMP command.
	// The current runc pre-dump approach, however, is
	// start criu in PRE_DUMP once for a single pre-dump
	// and not the whole series of pre-dump, pre-dump, ...m, dump
	// If we got the message CriuReqType_PRE_DUMP it means
	// CRIU was successful and we need to forcefully stop CRIU
	if !st.Success() && *req.Type != criurpc.CriuReqType_PRE_DUMP {
		return fmt.Errorf("criu failed: %s\nlog file: %s", st.String(), logPath)
	}
	return nil
}


func unlockNetwork(config *configs.Config) error {
	for _, config := range config.Networks {
		strategy, err := getStrategy(config.Type)
		if err != nil {
			return err
		}
		if err = strategy.attach(config); err != nil {
			return err
		}
	}
	return nil
}

func (c *freebsdContainer) criuNotifications(resp *criurpc.CriuResp, process *Process, opts *CriuOpts, fds []string, oob []byte) error {
	notify := resp.GetNotify()
	if notify == nil {
		return fmt.Errorf("invalid response: %s", resp.String())
	}
	logrus.Debugf("notify: %s\n", notify.GetScript())
	switch {
	case notify.GetScript() == "post-dump":
		f, err := os.Create(filepath.Join(c.root, "checkpoint"))
		if err != nil {
			return err
		}
		f.Close()
	case notify.GetScript() == "network-unlock":
		if err := unlockNetwork(c.config); err != nil {
			return err
		}
	case notify.GetScript() == "network-lock":
		if err := lockNetwork(c.config); err != nil {
			return err
		}
	case notify.GetScript() == "setup-namespaces":
		if c.config.Hooks != nil {
			s := configs.HookState{
				Version: c.config.Version,
				ID:      c.id,
				Pid:     int(notify.GetPid()),
				Bundle:  utils.SearchLabels(c.config.Labels, "bundle"),
			}
			for i, hook := range c.config.Hooks.Prestart {
				if err := hook.Run(s); err != nil {
					return newSystemErrorWithCausef(err, "running prestart hook %d", i)
				}
			}
		}
	case notify.GetScript() == "post-restore":
		pid := notify.GetPid()
		r, err := newRestoredProcess(int(pid), fds)
		if err != nil {
			return err
		}
		process.ops = r
		if err := c.state.transition(&restoredState{
			imageDir: opts.ImagesDirectory,
			c:        c,
		}); err != nil {
			return err
		}
		// create a timestamp indicating when the restored checkpoint was started
		c.created = time.Now().UTC()
		//if _, err := c.updateState(r); err != nil {
		if _, err := c.updateState(); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(c.root, "checkpoint")); err != nil {
			if !os.IsNotExist(err) {
				logrus.Error(err)
			}
		}
	case notify.GetScript() == "orphan-pts-master":
		scm, err := syscall.ParseSocketControlMessage(oob)
		if err != nil {
			return err
		}
		fds, err := syscall.ParseUnixRights(&scm[0])

		master := os.NewFile(uintptr(fds[0]), "orphan-pts-master")
		defer master.Close()

		// While we can access console.master, using the API is a good idea.
		if err := utils.SendFd(process.ConsoleSocket, master); err != nil {
			return err
		}
	}
	return nil
}
