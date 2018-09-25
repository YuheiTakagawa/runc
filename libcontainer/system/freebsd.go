// +build freebsd
package system
import(
	"golang.org/x/sys/unix"
)
func Prlimit(pid int, resource int, limit unix.Rlimit) error {
	err := unix.Setrlimit(resource, &limit)
	return err
}
