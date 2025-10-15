# Repository structure

The Contiki-NG repository is structured as follows:

## Core Directories

* **`os/`**: Contains the platform-independent Contiki-NG operating system code. Includes system primitives such as processes and timers, the complete networking stack, and all libraries and services. All examples compile and link against `os/`. See [doc:contiki-ng] for more information.
  * `os/sys/`: System primitives (processes, timers, memory management)
  * `os/net/`: Complete networking stack (IPv6, 6LoWPAN, RPL, CoAP, MQTT, etc.)
  * `os/dev/`: Device driver APIs and hardware abstraction layers
  * `os/lib/`: Core libraries and data structures
  * `os/services/`: Higher-level services (shell, orchestra, etc.)
  * `os/storage/`: Storage systems (Coffee file system, etc.)

* **`arch/`**: Contains all hardware-dependent code organized by CPU and platform.
  * `arch/cpu/`: CPU-specific code (startup, drivers for on-chip peripherals, timers, etc.)
  * `arch/platform/`: Platform-specific code (board initialization, off-chip peripherals, LEDs, buttons, sensors)
  * `arch/dev/`: Device-specific drivers that may be shared across platforms

  This is where to put your code if you are porting Contiki-NG to your own platform. See the [Porting Guide](Porting-Contiki-NG-to-new-platforms.md) for detailed instructions. Current platforms are documented at [doc:platforms].

* **`examples/`**: Contains ready-to-use example projects demonstrating how to use Contiki-NG features.
  * Platform-independent examples (hello-world, rpl-udp, coap, mqtt-client, etc.)
  * `examples/platform-specific/`: Platform-specific examples showcasing unique hardware features
  * Includes RPL border router, slip-radio interface, and various networking demonstrations

  To write your own application, start from one of the examples and follow our tutorials at [doc:tutorials].

* **`tools/`**: Contains development tools that run on the host computer (not included in firmware).
  * `tools/cooja/`: Cooja network simulator (as a Git submodule)
  * `tools/cc2538-bsl/`: Bootloader and flashing tools
  * `tools/code-style/`: Code style checking and formatting scripts (uncrustify)
  * `tools/vagrant/` and `tools/docker/`: Development environment scripts
  * Various other utilities for development and testing

* **`tests/`**: Contains all continuous integration (CI) tests.
  * Compilation tests for all platforms
  * Simulation tests using Cooja
  * Native platform tests
  * All tests run automatically for every pull request to ensure non-regression

* **`doc/`**: Contains all documentation in Markdown format.
  * `doc/getting-started/`: Getting started guides and tutorials
  * `doc/programming/`: Programming guides (including this file)
  * `doc/platforms/`: Platform-specific documentation
  * `doc/tutorials/`: Step-by-step tutorials
  * `doc/project/`: Project policies and contribution guidelines

## Additional Directories

* **`.github/`**: GitHub-specific configuration.
  * `workflows/`: GitHub Actions CI/CD workflow definitions
  * `dependabot.yml`: Automated dependency updates configuration

* **`.devcontainer/`**: VS Code development container configuration for consistent development environments.

* **`.claude/`**: Configuration for Claude Code (AI-assisted development).

## Build System Files

At the repository root, you'll find key build system files:
* `Makefile.include`: Main build system entry point included by all project Makefiles
* `Makefile.identify-target`: Target and board identification logic
* Various other `Makefile.*` files providing build system infrastructure

## Important Root Files

* `README.md`: Quick start guide and overview
* `LICENSE`: 3-clause BSD license
* `.gitmodules`: Git submodule configuration (Cooja simulator, vendor SDKs)
* `.gitignore`: Git ignore patterns for build artifacts
* `.uncrustify.cfg`: Code style configuration

[doc:contiki-ng]: /index.rst
[doc:platforms]: /doc/platforms/index.rst
[doc:tutorials]: /doc/tutorials/index.rst
