package main

import (
	"os"
	"time"
	"fmt"

	"github.com/urfave/cli"
)

// default action is to start a container
var runCommand = cli.Command{
	Name:  "run",
	Usage: "create and run a container",
	ArgsUsage: `<container-id>

Where "<container-id>" is your name for the instance of the container that you
are starting. The name you provide for the container instance must be unique on
your host.`,
	Description: `The run command creates an instance of a container for a bundle. The bundle
is a directory with a specification file named "` + specConfig + `" and a root
filesystem.

The specification file includes an args parameter. The args parameter is used
to specify command(s) that get run when the container is started. To change the
command(s) that get executed on start, edit the args parameter of the spec. See
"runc spec --help" for more explanation.`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "pid-file",
			Value: "",
			Usage: "specify the file to write the process id to",
		},
	},
	Action: func(context *cli.Context) error {
		file, _ := os.OpenFile("/restore.time", os.O_WRONLY|os.O_APPEND, 0666)
		fmt.Fprintln(file, "ru")
		fmt.Fprintln(file, time.Now().UnixNano())
		file.Close()
		if err := checkArgs(context, 1, exactArgs); err != nil {
			return err
		}
		if err := revisePidFile(context); err != nil {
			return err
		}
		spec, err := setupSpec(context)
		if err != nil {
			return err
		}
		status, err := startContainer(context, spec, CT_ACT_RUN, nil)
		if err == nil {
			// exit with the container's exit status so any external supervisor is
			// notified of the exit with the correct exit status.
			os.Exit(status)
		}
		return err
	},
}
