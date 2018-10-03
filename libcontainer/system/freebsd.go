// +build freebsd

package system

import (
	"bytes"
	"os/exec"

	"golang.org/x/sys/unix"
)

func Prlimit(pid int, resource int, limit unix.Rlimit) error {
	err := unix.Setrlimit(resource, &limit)
	return err
}

func RctlAdd(jid string, resource string, action string, amount string) error {
	var buffer bytes.Buffer
	buffer.WriteString("jail:")
	buffer.WriteString(jid)
	buffer.WriteString(":")
	buffer.WriteString(resource)
	buffer.WriteString(":")
	buffer.WriteString(action)
	buffer.WriteString("=")
	buffer.WriteString(amount)
	buffer.WriteString("/jail")
	str := buffer.String()
	err := exec.Command("rctl", "-a", str).Run()

	return err
}

func RctlRemove(jname string) error {
	str := "jail:" + jname
	err := exec.Command("rctl", "-r", str).Run()
	return err
}


func Cpuset(jname, cpuset string) error {
	err := exec.Command("cpuset", "-l", cpuset, "-j", jname).Run()
	return err
}
