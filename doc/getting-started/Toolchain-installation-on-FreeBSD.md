# Toolchain installation on FreeBSD

This page describes how to build and run Contiki-NG for the native platform
on FreeBSD, and how to run the native tests. It has been tested on
FreeBSD 15.1 on amd64.

## Install development tools for Contiki-NG

Install the build tools with `pkg`:

```bash
$ sudo pkg install git gcc gmake bash python3
```

The native platform is compiled with `gcc`, so the `cc` of the base system
is not enough. The `python3` package provides the `python3` command, which
the versioned Python packages do not install.

To run the tests in `tests/08-native-runs`, also install the programs that
they talk to the native nodes with:

```bash
$ sudo pkg install libcoap net-snmp mosquitto valgrind
```

## Use GNU Make

The Contiki-NG build system needs GNU Make. On FreeBSD, `make` is BSD Make,
so run `gmake` wherever the documentation says `make`:

```bash
$ cd examples/hello-world
$ gmake TARGET=native
$ ./build/native/hello-world.native
```

## Networking

A native node with IPv6 networking opens the tun device `/dev/tun0`, and
configures it with `ifconfig`, which needs root:

```bash
$ sudo ./build/native/hello-world.native
```

FreeBSD creates the device when it is first opened. Without root, the node
runs without a network.

The tests that need root run themselves under `sudo`, so they expect it not
to ask for a password.

## Hardened systems

The FreeBSD installer offers to harden the system. One of those settings,
`security.bsd.unprivileged_proc_debug=0`, stops valgrind, which the MQTT
tests under valgrind then report as a failure. Allow it again with:

```bash
$ sudo sysctl security.bsd.unprivileged_proc_debug=1
```

## Other platforms

The `arm-none-eabi-gcc` package does not include newlib-nano or the C
libraries for the different Cortex-M variants, so it cannot link firmware
for the ARM platforms. Build such firmware on another host, or with another
ARM toolchain.

The tools that flash a platform differ from one platform to another, and many
of them are not available for FreeBSD.

## Clone Contiki-NG

```bash
$ git clone https://github.com/contiki-ng/contiki-ng.git
$ cd contiki-ng
$ git submodule update --init --recursive
```
