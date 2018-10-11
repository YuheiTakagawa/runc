# FreeBSD runc

[![Build Status](https://travis-ci.org/opencontainers/runc.svg?branch=master)](https://travis-ci.org/opencontainers/runc)
[![Go Report Card](https://goreportcard.com/badge/github.com/opencontainers/runc)](https://goreportcard.com/report/github.com/opencontainers/runc)
[![GoDoc](https://godoc.org/github.com/opencontainers/runc?status.svg)](https://godoc.org/github.com/opencontainers/runc)

## Introduction

`runc` is a CLI tool for spawning and running containers according to the OCI specification.

This is an experiment for implementing a FreeBSD runtime for `runc`.
Some of runc commands have been implemented:
create, delete, exec, kill, list, ps, run, spec, start, state

The commands: init, checkpoint, restore, update, events, and pause/resume are not supported yet.

FreeBSD Jail is not a child process, so 'init' does not make any sense on FreeBSD platform.

## Releases

`runc` depends on and tracks the [runtime-spec](https://github.com/opencontainers/runtime-spec) repository.
We will try to make sure that `runc` and the OCI specification major versions stay in lockstep.
This means that `runc` 1.0.0 should implement the 1.0 version of the specification.

You can find official releases of `runc` on the [release](https://github.com/opencontainers/runc/releases) page.

### Security

If you wish to report a security issue, please disclose the issue responsibly
to security@opencontainers.org.

## Building

`runc` currently supports the Linux platform with various architecture support.
It must be built with Go version 1.6 or higher in order for some features to function properly.

       (2) prepare config.json:
       ./runc spec
       sed -i 's;"sh";"/bin/sh";' config.json

       (3) launch a shell:
       ./runc run test


```bash
# create a 'github.com/opencontainers' in your GOPATH/src
cd github.com/opencontainers
git clone https://github.com/clovertrail/runc.git
cd runc

make
sudo make install
```

`runc` will be installed to `/usr/local/sbin/runc` on your system.

### Dependencies Management

`runc` uses [vndr](https://github.com/LK4D4/vndr) for dependencies management.
Please refer to [vndr](https://github.com/LK4D4/vndr) for how to add or update
new dependencies.

## Using runc

### Creating an FreeBSD OCI Bundle

In order to use runc you must have your container in the format of an OCI bundle.
If you have Docker installed you can use its `export` method to acquire a root filesystem from an existing Docker container.

```bash
# create the top most bundle directory
mkdir /mycontainer
cd /mycontainer

# create the rootfs directory
mkdir rootfs

# Download FreeBSD 11.0 release image files (base.txz and lib32.txz) from official site:
fetch ftp://ftp.freebsd.org/pub/FreeBSD/releases/amd64/amd64/11.0-RELEASE/base.txz
fetch ftp://ftp.freebsd.org/pub/FreeBSD/releases/amd64/amd64/11.0-RELEASE/lib32.txz

tar xvf base.txz -C rootfs
tar xvf lib32.txz -C rootfs

```
After a root filesystem is populated you just generate a spec in the format of a `config.json` file inside your bundle.
`runc` provides a `spec` command to generate a base template spec that you are then able to edit.
To find features and documentation for fields in the spec please refer to the [specs](https://github.com/opencontainers/runtime-spec) repository.

```bash
runc spec
```

### Running Containers

Assuming you have an OCI bundle from the previous step you can execute the container in two different ways.

The first way is to use the convenience command `run` that will handle creating, starting, and deleting the container after it exits.

```bash
# run as root
cd /mycontainer
runc run mycontainerid
```

If you used the unmodified `runc spec` template this should give you a `sh` session inside the container.

The second way to start a container is using the specs lifecycle operations.
This gives you more power over how the container is created and managed while it is running.
This will also launch the container and pop up a shell for you.
Your process field in the `config.json` should look like this below with `"args": ["/bin/sh"]`.


```json
        "process": {
                "terminal": true,
                "user": {
                        "uid": 0,
                        "gid": 0
                },
                "args": [
                        "/bin/sh"
                ],
                "env": [
                        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        "TERM=xterm"
                ],
                "cwd": "/",
                "capabilities": [
                        "CAP_AUDIT_WRITE",
                        "CAP_KILL",
                        "CAP_NET_BIND_SERVICE"
                ],
                "rlimits": [
                        {
                                "type": "RLIMIT_NOFILE",
                                "hard": 1024,
                                "soft": 1024
                        }
                ],
                "noNewPrivileges": true
        },
```

Now we can go though the lifecycle operations in your shell.


```bash
# run as root
cd /mycontainer
runc create mycontainerid

# view the container is created and in the "created" state
runc list

# start the process inside the container
runc run mycontainerid

# after 5 seconds view that the container has exited and is now in the stopped state
runc list

# now delete the container
runc delete mycontainerid
```
