# Porting Contiki-NG to new platforms

**Last Updated:** January 2025
**Applies to:** Contiki-NG develop branch

This guide will show you how to port Contiki-NG to a new hardware device. The guide assumes that your device is an IoT-type device with the following characteristics:

* A microcontroller (e.g. Arm Cortex, msp430- or avr-based), plus on-chip peripherals (such as UART, SPI, I2C, DMA...).
* A radio (either integrated on the same chip as your MCU, or on a separate chip). This can be e.g. a standard IEEE 802.15.4 radio operating at the 2.4GHz band, a sub-ghz radio, or a BLE radio.
* Various off-chip peripherals, e.g. LEDs, buttons, sensors.

## Table of Contents

1. [Before You Start](#before-you-start)
   - [Prerequisites](#prerequisites)
   - [Understanding the Architecture](#understanding-the-architecture)
   - [Do You Need CPU Support, Platform Support, or Both?](#do-you-need-cpu-support-platform-support-or-both)
2. [Quick Reference Checklist](#quick-reference-checklist)
3. [Porting Overview](#porting-overview)
4. [CPU Code](#cpu-code)
   - [Configure the Build System](#configure-the-build-system)
   - [Develop Essential CPU Drivers](#develop-essential-cpu-drivers)
   - [Linker Scripts and Memory Layout](#linker-scripts-and-memory-layout)
   - [Startup Code and Entry Points](#startup-code-and-entry-points)
   - [Interrupt Handlers](#interrupt-handlers)
   - [Additional CPU Drivers](#additional-cpu-drivers)
5. [Platform Code](#platform-code)
   - [Prepare the Configuration System](#prepare-the-configuration-system)
   - [Configure the Build System](#configure-the-build-system-1)
   - [Provide Startup, Main Loop and Low-Power Functions](#provide-startup-main-loop-and-low-power-functions)
   - [Develop Platform Drivers](#develop-platform-drivers)
   - [Add Support for Similar Board Variants](#add-support-for-similar-board-variants)
6. [Testing and Validation](#testing-and-validation)
   - [Driver Development Progression Path](#driver-development-progression-path)
   - [Create Examples](#create-examples)
   - [Add CI Tests](#add-ci-tests)
7. [Documentation](#documentation)
8. [Common Good Practices](#common-good-practices)
9. [Troubleshooting](#troubleshooting)
10. [Examples of Successful Ports](#examples-of-successful-ports)
11. [Support](#support)

---

## Before You Start

### Prerequisites

This guide assumes you have:

**Required Knowledge:**
- Solid understanding of the C programming language
- Familiarity with GNU Make and Makefiles
- Basic understanding of embedded systems development
- Knowledge of your target hardware's architecture and peripherals

**Required Reading:**
1. [The Contiki-NG build system][doc:build-system] - Understand `TARGET`, `BOARD`, and `MODULES` concepts
2. [Multitasking and scheduling][doc:multitasking-and-scheduling] - Understand the process model and interrupt safety

**Development Environment:**
- GNU Make 4.0 or newer
- Appropriate cross-compilation toolchain for your target (e.g., `arm-none-eabi-gcc` for ARM Cortex-M)
- Hardware debugging tools (JTAG/SWD debugger recommended)
- Serial terminal software for debugging output

**Hardware Documentation:**
- CPU reference manual
- Platform/board schematics
- Peripheral datasheets
- Radio transceiver documentation

### Understanding the Architecture

Contiki-NG's hardware abstraction is organized into three layers:

```
┌─────────────────────────────────────────────────────────────┐
│  Application Layer (examples/, user code)                    │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│  Platform-Independent OS (os/)                               │
│  - Networking stack, processes, timers, libraries            │
└─────────────────────────────────────────────────────────────┘
                            │
         ┌──────────────────┴──────────────────┐
         │                                     │
┌────────▼─────────────┐          ┌───────────▼──────────────┐
│  Platform Layer      │          │  CPU Layer               │
│  (arch/platform/)    │          │  (arch/cpu/)             │
│                      │          │                          │
│  - Board-specific    │          │  - MCU-specific drivers  │
│  - Off-chip devices  │          │  - Core peripherals      │
│  - LEDs, buttons     │          │  - Timers, interrupts    │
│  - Sensors           │◄─────────┤  - On-chip radio         │
│  - External storage  │          │  - Memory, DMA           │
└──────────────────────┘          └──────────────────────────┘
         │                                     │
         └──────────────────┬──────────────────┘
                            │
                    ┌───────▼────────┐
                    │    Hardware    │
                    └────────────────┘
```

**Key Concepts:**
- **CPU (arch/cpu/)**: Everything _inside_ the main chip - CPU core, on-chip peripherals, integrated radio
- **Platform (arch/platform/)**: Everything _outside_ the main chip - LEDs, buttons, sensors, external components
- **Board**: A variant of a platform with slight differences (e.g., different peripherals or connectivity)
- **Target**: The make variable that identifies the platform (e.g., `TARGET=zoul`)

### Do You Need CPU Support, Platform Support, or Both?

**Answer these questions:**

1. **Is your MCU already supported?**
   - Check `arch/cpu/` for your MCU family
   - If yes → Skip to [Platform Code](#platform-code)
   - If no → Start with [CPU Code](#cpu-code)

2. **Are you using a development board from a supported platform?**
   - Check `arch/platform/` for your board
   - If supported with minor differences → See [Board Variants](#add-support-for-similar-board-variants)
   - If completely new → Implement both CPU and Platform code

3. **Which existing platform is closest to yours?**

   | Your MCU Family | Reference Platform | Location |
   |-----------------|-------------------|----------|
   | ARM Cortex-M3 | CC2538, OpenMote | `arch/cpu/cc2538/`, `arch/platform/openmote/` |
   | ARM Cortex-M4 | CC26xx/CC13xx | `arch/cpu/cc26x0-cc13x0/`, `arch/platform/cc26x0-cc13x0/` |
   | ARM Cortex-M4F | nRF52840 | `arch/cpu/nrf52840/`, `arch/platform/nrf/` |
   | MSP430 | Z1, Sky | `arch/cpu/msp430/`, `arch/platform/z1/` |
   | Native (POSIX) | Native | `arch/platform/native/` |

---

## Quick Reference Checklist

Use this checklist to track your porting progress:

### CPU Code (if needed)
- [ ] Create `arch/cpu/my-new-mcu/` directory
- [ ] **Essential files:**
  - [ ] `Makefile.my-new-mcu` - Build configuration
  - [ ] `my-new-mcu-def.h` - Non-modifiable MCU definitions
  - [ ] `my-new-mcu-conf.h` - User-modifiable MCU configuration
  - [ ] `doxygen-group.txt` - API documentation grouping
- [ ] **Linker and startup:**
  - [ ] Linker script (`.ld` file) - Memory layout
  - [ ] Startup code (e.g., `startup-my-new-mcu.c`) - Boot sequence
- [ ] **Essential drivers (Phase 1 - Minimal Boot):**
  - [ ] `clock.c` - Software clock implementation
  - [ ] `rtimer-arch.c` - High-resolution timer
  - [ ] Basic UART/printf support for debugging
- [ ] **Core functionality (Phase 2):**
  - [ ] `int-master.h` implementation - Interrupt enable/disable
  - [ ] `watchdog.c` - Watchdog timer driver
- [ ] **Extended drivers (Phase 3):**
  - [ ] GPIO HAL implementation
  - [ ] Serial line input (for shell)
  - [ ] Radio driver (if on-chip)
  - [ ] RNG driver
  - [ ] SPI/I2C/ADC drivers
  - [ ] DMA support (if applicable)

### Platform Code
- [ ] Create `arch/platform/my-platform/` directory
- [ ] **Essential files:**
  - [ ] `Makefile.my-platform` - Build configuration
  - [ ] `platform.c` - Platform initialization functions
  - [ ] `contiki-conf.h` - Platform configuration
  - [ ] `my-platform-def.h` - Platform-specific definitions (optional)
  - [ ] `doxygen-group.txt` - API documentation grouping
- [ ] **Required functions in platform.c:**
  - [ ] `platform_init_stage_one()`
  - [ ] `platform_init_stage_two()`
  - [ ] `platform_init_stage_three()`
  - [ ] `platform_idle()` - Low-power mode
  - [ ] `platform_main_loop()` - If custom loop needed
- [ ] **Platform drivers:**
  - [ ] `leds-arch.c` - LED driver
  - [ ] `board-buttons.c` - Button driver
  - [ ] Sensor drivers
  - [ ] External storage driver (if applicable)
  - [ ] Display driver (if applicable)

### Testing and Documentation
- [ ] Hello World example works
- [ ] Timer/event example works
- [ ] Networking example works (if applicable)
- [ ] Platform-specific examples created
- [ ] CI compile tests added
- [ ] README files written
- [ ] API documentation (doxygen) completed
- [ ] Wiki page created

---

## Porting Overview

Creating a Contiki-NG port involves these high-level steps:

1. **[Adding support for your CPU](#cpu-code)** _(skip if already supported)_
   - Developing drivers and arch-specific modules for your CPU
   - Extending the Contiki-NG build system for your CPU
   - Implementing linker scripts and memory layout
   - Writing startup code and interrupt handlers

2. **[Adding support for your platform](#platform-code)**
   - Developing drivers for off-chip peripherals
   - Extending the Contiki-NG build system for your platform
   - Implementing platform initialization and power management

3. **[Writing and testing examples](#testing-and-validation)**
   - Creating platform-specific examples
   - Testing existing examples on your hardware

4. **[Adding CI tests](#add-ci-tests)**
   - Adding compile tests for your platform

5. **[Creating documentation](#documentation)**
   - API docs, guides, and README files

---

## CPU Code

**Difficulty:** ⚠️ Advanced - Required only if your MCU is not yet supported

If your CPU is already supported by Contiki-NG, skip to the "[Platform code](#platform-code)" section.

Let's assume that your MCU is called `my-new-mcu`.

**Initial Setup:**

1. Create a directory under `arch/cpu/` and name it `my-new-mcu`.
2. Under `arch/cpu/my-new-mcu`, create the following files:
   - `Makefile.my-new-mcu`: Build system configuration for your MCU
   - `my-new-mcu-conf.h`: User-modifiable MCU configuration macros
   - `my-new-mcu-def.h`: Non-modifiable MCU definitions and constants
   - `doxygen-group.txt`: Documentation structure definition

**Example `doxygen-group.txt`:**
```
/**
 * \defgroup my-new-mcu My New MCU
 * @{
 *
 * Documentation for My New MCU
 */
```

See [`arch/cpu/cc2538/doxygen-group.txt`](https://github.com/contiki-ng/contiki-ng/tree/develop/arch/cpu/cc2538/doxygen-group.txt) for a complete example.

### Configure the Build System

**Difficulty:** ⚠️ Advanced

Your `Makefile.my-new-mcu` must specify CPU-dependent source files and build rules.

**Step 1: Specify source files**

Append to the `CONTIKI_SOURCEFILES` make variable:

```Makefile
#### CPU-dependent source files
CONTIKI_CPU_SOURCEFILES += soc.c clock.c rtimer-arch.c uart.c watchdog.c
CONTIKI_CPU_SOURCEFILES += gpio-hal.c int-master.c

DEBUG_IO_SOURCEFILES += dbg-printf.c dbg-snprintf.c dbg-sprintf.c strformat.c

USB_SOURCEFILES += usb-core.c cdc-acm.c usb-arch.c usb-serial.c cdc-acm-descriptors.c

#### Actually instruct the system to build all of the above
CONTIKI_SOURCEFILES += $(CONTIKI_CPU_SOURCEFILES) $(DEBUG_IO_SOURCEFILES)
CONTIKI_SOURCEFILES += $(USB_SOURCEFILES)
```

**Step 2: Choose your build infrastructure**

**For ARM Cortex-M based MCUs:**

You can leverage existing CM3/CM4 infrastructure by including the appropriate Makefile:

```Makefile
# For Cortex-M3
include $(CONTIKI)/arch/cpu/arm/cortex-m/cm3/Makefile.cm3

# For Cortex-M4
include $(CONTIKI)/arch/cpu/arm/cortex-m/cm4/Makefile.cm4
```

This automatically configures:
- Toolchain (arm-none-eabi-gcc)
- Common CFLAGS and LDFLAGS
- Build targets and rules
- Cortex-M specific startup code

You can extend or override these settings in your Makefile.

**For non-Cortex MCUs:**

You must specify:

1. **Toolchain:**
```Makefile
CC       = my-mcu-gcc
LD       = my-mcu-gcc
AS       = my-mcu-as
AR       = my-mcu-ar
OBJCOPY  = my-mcu-objcopy
OBJDUMP  = my-mcu-objdump
```

2. **Compilation and linking flags:**
```Makefile
CFLAGS   += -mmcu=my-new-mcu -DMY_MCU_DEFINE
LDFLAGS  += -mmcu=my-new-mcu -Wl,--gc-sections
```

3. **Custom compilation rule (if needed):**
```Makefile
CUSTOM_RULE_C_TO_OBJECTDIR_O = 1

$(OBJECTDIR)/%.o: %.c | $(OBJECTDIR)
	$(CC) $(CFLAGS) -c $< -o $@
```

4. **Custom link rule (if needed):**
```Makefile
CUSTOM_RULE_LINK = 1

%.$(TARGET): %.co $(PROJECT_OBJECTFILES) $(PROJECT_LIBRARIES) contiki-$(TARGET).a
	$(LD) $(LDFLAGS) -o $@ $(filter-out %.a,$^) $(filter %.a,$^) $(LDLIBS)
```

**Best Practice:** Study existing CPU Makefiles for your architecture family. Try to reuse existing infrastructure where possible.

**Common Makefile Variables Reference:**

| Variable | Purpose | Example |
|----------|---------|---------|
| `CONTIKI_SOURCEFILES` | Source files to compile | `clock.c rtimer-arch.c` |
| `MODULES` | Additional module directories | `arch/dev/cc1200` |
| `CFLAGS` | Compiler flags | `-O2 -Wall -g` |
| `LDFLAGS` | Linker flags | `-Wl,--gc-sections` |
| `OBJCOPY_FLAGS` | objcopy flags for firmware | `--gap-fill 0xff` |
| `CONTIKI_CPU_DIRS` | Additional CPU include paths | `./dev ./lib` |

### Linker Scripts and Memory Layout

**Difficulty:** ⚠️ Advanced - **Essential** for proper firmware operation

Most embedded targets require a linker script (`.ld` file) to define memory layout and section placement.

**What the linker script defines:**
- Flash (ROM) and RAM addresses and sizes
- Code section placement (.text, .rodata)
- Data section placement (.data, .bss)
- Stack and heap locations and sizes
- Interrupt vector table location
- Special sections (e.g., bootloader, configuration)

**Example linker script structure:**

```ld
/* Memory layout for my-new-mcu */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 256K
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}

SECTIONS
{
  .text :
  {
    KEEP(*(.vectors))      /* Interrupt vectors first */
    *(.text*)              /* Code */
    *(.rodata*)            /* Read-only data */
  } > FLASH

  .data :
  {
    *(.data*)              /* Initialized data */
  } > RAM AT > FLASH

  .bss :
  {
    *(.bss*)               /* Uninitialized data */
    *(COMMON)
  } > RAM
}
```

**Reference your linker script in the Makefile:**

```Makefile
LDSCRIPT = $(CONTIKI_CPU)/my-new-mcu.ld
LDFLAGS += -T $(LDSCRIPT)
```

**Flash Layout Considerations:**

For embedded systems, plan your flash organization:

```
┌─────────────────────────┐  0x00000000
│  Interrupt Vectors      │
├─────────────────────────┤  0x00000400
│  Application Code       │
│  (.text)                │
│                         │
├─────────────────────────┤
│  Read-Only Data         │
│  (.rodata)              │
├─────────────────────────┤
│  Initialized Data Image │
│  (copied to RAM)        │
├─────────────────────────┤
│  Configuration/NVM      │
│  (optional)             │
└─────────────────────────┘  End of Flash
```

**Common Issues:**
- Stack overflow: Ensure adequate stack size
- Heap exhaustion: Configure heap size appropriately
- Section overlap: Verify addresses don't conflict
- Vector table alignment: Some MCUs require specific alignment

### Startup Code and Entry Points

**Difficulty:** ⚠️ Advanced - **Essential** for CPU initialization

**The Boot Sequence:**

1. **Hardware reset** → MCU starts at reset vector
2. **Startup code** → Initialize CPU, copy .data, clear .bss
3. **`main()`** → Contiki-NG's platform-independent main
4. **Platform init** → Your platform-specific initialization
5. **OS init** → Contiki-NG OS initialization
6. **Main loop** → Event processing and scheduling

**Your Responsibilities:**

Contiki-NG provides the platform-independent `main()` function in [`os/contiki-main.c`](https://github.com/contiki-ng/contiki-ng/tree/develop/os/contiki-main.c). You need to ensure this function is called after your CPU initialization.

**Typical startup code structure** (e.g., `startup-my-new-mcu.c`):

```c
/* Interrupt vector table */
__attribute__ ((section(".vectors")))
void (* const vectors[])(void) = {
    (void (*)(void))&_stack_top,     /* Initial stack pointer */
    reset_handler,                    /* Reset handler */
    nmi_handler,                      /* NMI handler */
    hardfault_handler,                /* Hard fault handler */
    /* ... more interrupt vectors ... */
};

/* Reset handler - called on startup */
void reset_handler(void)
{
    /* Copy .data section from flash to RAM */
    uint32_t *src = &_etext;
    uint32_t *dst = &_data;
    while(dst < &_edata) {
        *dst++ = *src++;
    }

    /* Zero .bss section */
    dst = &_bss;
    while(dst < &_ebss) {
        *dst++ = 0;
    }

    /* Call system initialization (clocks, peripherals) */
    system_init();

    /* Jump to Contiki-NG main() */
    main();

    /* Should never return */
    while(1);
}
```

**For Cortex-M MCUs:** The CM3/CM4 infrastructure already provides startup code. You typically only need to:
1. Define `SystemInit()` function for early CPU initialization
2. Ensure the linker script references the correct startup file

**Key Points:**
- Initialize CPU clocks early (before any timing-dependent code)
- Do not enable interrupts in startup code (Contiki-NG handles this)
- Minimal initialization here - detailed setup goes in platform_init functions
- The reset handler must never return

### Develop Essential CPU Drivers

**Difficulty:** ⚠️⚠️ Advanced - These are **mandatory** for a working port

#### Phase 1: Minimal Boot (Essential)

These drivers are required to boot Contiki-NG and run basic examples:

**1. Software Clock (clock.c)** - ⚠️⚠️ **Mandatory**

Provides the system tick and timing functions.

**API to implement** (from [`os/sys/clock.h`](https://github.com/contiki-ng/contiki-ng/tree/develop/os/sys/clock.h)):

```c
void clock_init(void);                    /* Initialize clock */
clock_time_t clock_time(void);            /* Get current time in ticks */
unsigned long clock_seconds(void);        /* Get seconds since boot */
void clock_wait(clock_time_t t);          /* Busy-wait for t ticks */
void clock_delay_usec(uint16_t dt);       /* Busy-wait for dt microseconds */
```

**Configuration required in `my-new-mcu-def.h`:**

```c
/* Clock tick frequency (Hz) - how often the clock interrupt fires */
#define CLOCK_CONF_SECOND 128

/* Size of clock_time_t - use largest type that fits your needs */
#define CLOCK_CONF_SIZE 4  /* 4 bytes = 32-bit counter */
```

**Choosing `CLOCK_CONF_SECOND`:**
- Common values: 128, 256, 1024
- Trade-offs:
  - Higher values: Better time resolution, more frequent interrupts (higher power)
  - Lower values: Longer time until overflow, less CPU overhead
- Must be achievable with your hardware timer

**Typical implementation:**

```c
static volatile clock_time_t current_clock = 0;
static volatile unsigned long current_seconds = 0;
static unsigned int second_countdown = CLOCK_CONF_SECOND;

void clock_init(void)
{
    /* Configure hardware timer to interrupt at CLOCK_CONF_SECOND Hz */
    /* Example: Configure Timer0 to interrupt every 1/CLOCK_CONF_SECOND seconds */
}

/* Timer interrupt handler */
void timer_isr(void)
{
    current_clock++;

    if(--second_countdown == 0) {
        current_seconds++;
        second_countdown = CLOCK_CONF_SECOND;
    }

    /* Notify process scheduler if etimer needs servicing */
    if(etimer_pending()) {
        etimer_request_poll();
    }
}

clock_time_t clock_time(void)
{
    return current_clock;
}

unsigned long clock_seconds(void)
{
    return current_seconds;
}
```

**2. Real-Time Timer (rtimer-arch.c)** - ⚠️⚠️ **Mandatory**

Provides high-resolution timing for time-critical operations (e.g., TSCH, radio timestamping).

**API to implement** (from [`os/sys/rtimer.h`](https://github.com/contiki-ng/contiki-ng/tree/develop/os/sys/rtimer.h)):

```c
void rtimer_arch_init(void);                          /* Initialize rtimer */
rtimer_clock_t rtimer_arch_now(void);                 /* Get current time */
void rtimer_arch_schedule(rtimer_clock_t t);          /* Schedule callback at time t */
```

**Configuration in `my-new-mcu-def.h`:**

```c
/* Rtimer clock frequency (Hz) - typically much higher than CLOCK_CONF_SECOND */
#define RTIMER_ARCH_SECOND 32768  /* 32 kHz is common */

/* Size of rtimer_clock_t */
typedef uint32_t rtimer_clock_t;
#define RTIMER_CLOCK_DIFF(a,b) ((int32_t)((a)-(b)))
```

**Requirements:**
- Must use a different hardware timer than the software clock
- Should provide microsecond-level or better resolution
- Critical for TSCH and radio timestamping accuracy

**3. Debug Output (UART + printf)** - ⚠️ **Highly Recommended**

Enables `printf()` for debugging - absolutely essential during development.

**Approach 1: Minimal putchar implementation**

```c
/* In uart.c */
int putchar(int c)
{
    /* Wait for UART to be ready */
    while(!(UART0->STATUS & UART_TX_READY));

    /* Send character */
    UART0->DATA = c;

    /* Convert \n to \r\n for proper line endings */
    if(c == '\n') {
        putchar('\r');
    }

    return c;
}
```

**Approach 2: Use Contiki-NG's lightweight printf**

The [`os/lib/dbg-io`](https://github.com/contiki-ng/contiki-ng/tree/develop/os/lib/dbg-io) library provides lightweight printf implementations that use less code space.

**In your Makefile:**
```Makefile
MODULES += os/lib/dbg-io
```

**Configuration:**
Ensure your `putchar()` or equivalent output function is called by the dbg-io library.

**Best Practice:** Get UART output working as early as possible - it will save hours of debugging time.

**4. Interrupt Management (int-master.h)** - ⚠️⚠️ **Mandatory**

Provides global interrupt enable/disable for critical sections.

**API to implement** (from [`os/sys/int-master.h`](https://github.com/contiki-ng/contiki-ng/tree/develop/os/sys/int-master.h)):

```c
/* Usually implemented as macros in my-new-mcu-def.h */

/* Disable all interrupts, return previous state */
int_master_status_t int_master_read_and_disable(void);

/* Restore interrupt state */
void int_master_status_set(int_master_status_t status);

/* Check if interrupts are enabled */
bool int_master_is_enabled(void);
```

**Example for ARM Cortex-M:**

```c
typedef uint32_t int_master_status_t;

#define int_master_read_and_disable() \
  ({ \
    int_master_status_t __status; \
    __asm__ volatile ("mrs %0, PRIMASK\n" \
                      "cpsid i" : "=r" (__status) :: "memory"); \
    __status; \
  })

#define int_master_status_set(status) \
  do { \
    __asm__ volatile ("msr PRIMASK, %0" :: "r" (status) : "memory"); \
  } while(0)

#define int_master_is_enabled() \
  ({ \
    int_master_status_t __status; \
    __asm__ volatile ("mrs %0, PRIMASK" : "=r" (__status) :: "memory"); \
    (__status & 1) == 0; \
  })
```

**Testing Milestone:** At this point, you should be able to compile and run a simple hello-world example that:
- Boots successfully
- Prints output via UART
- Uses timers and delays

### Interrupt Handlers

**Difficulty:** ⚠️⚠️ Advanced - **Critical for correct operation**

**⚠️ IMPORTANT: Interrupt Safety**

Many Contiki-NG functions are **NOT safe** to call from interrupt context. See [doc:multitasking-and-scheduling] for details.

**Safe in interrupts:**
- `process_poll()` - Request a process to run
- `etimer_request_poll()` - Notify etimer system
- Setting flags/variables (with proper volatile declaration)
- Hardware register access

**NOT safe in interrupts:**
- `process_post()` - Event posting (use `process_poll()` instead)
- Most networking functions
- File I/O operations
- Dynamic memory allocation
- Printf (may be safe but use cautiously)

**Best Practice Pattern:**

```c
/* Interrupt handler */
static volatile bool data_ready = false;

void uart_rx_isr(void)
{
    /* Minimal work in ISR */
    received_data = UART0->DATA;
    data_ready = true;

    /* Notify process to handle data */
    process_poll(&uart_process);

    /* Clear interrupt flag */
    UART0->INT_CLEAR = UART_RX_FLAG;
}

/* Process handles data outside interrupt context */
PROCESS_THREAD(uart_process, ev, data)
{
    PROCESS_BEGIN();

    while(1) {
        PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_POLL);

        if(data_ready) {
            data_ready = false;
            /* Safe to call complex functions here */
            handle_received_data(received_data);
        }
    }

    PROCESS_END();
}
```

**Interrupt Handler Checklist:**
- [ ] Keep ISRs short and fast
- [ ] Only call interrupt-safe functions
- [ ] Use `volatile` for variables shared with main code
- [ ] Clear interrupt flags appropriately
- [ ] Use `process_poll()` to defer processing
- [ ] Disable interrupts during critical sections if needed
- [ ] Test with interrupts from multiple sources

### Additional CPU Drivers

**Difficulty:** 📘 Moderate to Advanced - Implement based on your requirements

After achieving minimal boot, implement additional drivers based on priority:

#### Watchdog Timer (watchdog.c) - 📘 **Recommended**

Provides system reset capability for error recovery.

**API** (from [`os/dev/watchdog.h`](https://github.com/contiki-ng/contiki-ng/tree/develop/os/dev/watchdog.h)):

```c
void watchdog_init(void);        /* Initialize watchdog */
void watchdog_start(void);       /* Enable watchdog */
void watchdog_stop(void);        /* Disable watchdog */
void watchdog_periodic(void);    /* Reset/kick watchdog */
void watchdog_reboot(void);      /* Force immediate reboot */
```

#### GPIO HAL - 📘 **Recommended**

Provides generic GPIO access for buttons, LEDs, and general I/O.

**See** [`os/dev/gpio-hal.h`](https://github.com/contiki-ng/contiki-ng/tree/develop/os/dev/gpio-hal) for the hardware abstraction layer API.

**You implement:**
- Pin configuration (input/output, pull-up/pull-down)
- Pin read/write
- Interrupt configuration (edge/level triggered)
- Interrupt handlers

#### Serial Line Input - 📘 **Recommended**

Extends UART driver to receive console input, enables the Contiki-NG shell.

**Requirements:**
- UART receive interrupt handler
- Character buffering
- Line termination handling
- Integration with serial-line module

**See:** Existing implementations in CPU directories for examples.

#### Radio Driver (if on-chip) - ⚠️⚠️ **Required for networking**

One of the most complex drivers to implement.

**API** (from [`os/dev/radio.h`](https://github.com/contiki-ng/contiki-ng/tree/develop/os/dev/radio.h)):

```c
const struct radio_driver my_radio_driver = {
    init,              /* Initialize radio */
    prepare,           /* Prepare packet for transmission */
    transmit,          /* Transmit prepared packet */
    send,              /* Prepare and transmit in one call */
    read,              /* Read received packet */
    channel_clear,     /* CCA - channel assessment */
    receiving_packet,  /* Check if currently receiving */
    pending_packet,    /* Check if packet received */
    on,                /* Turn radio on */
    off,               /* Turn radio off */
    get_value,         /* Get radio parameter */
    set_value,         /* Set radio parameter */
    get_object,        /* Get radio object */
    set_object         /* Set radio object */
};
```

**Special Considerations for TSCH:**

If you want to support TSCH (Time-Slotted Channel Hopping), your radio driver must provide:
- Precise timestamping of packet transmission/reception
- Fast RX/TX turnaround times
- Accurate timing for slot boundaries
- Support for ACK handling within timing constraints

**See** [TSCH porting guide][doc:tsch] for detailed requirements.

**Common Radio Driver Challenges:**
- Interrupt timing and synchronization
- Buffer management (TX/RX queues)
- Power state transitions
- Calibration and frequency accuracy
- Frame filtering and addressing

#### Random Number Generator (RNG) - 📘 **Recommended**

Provides entropy for security and randomization.

**API** (from [`os/lib/random.h`](https://github.com/contiki-ng/contiki-ng/tree/develop/os/lib/random.h)):

```c
void random_init(unsigned short seed);
unsigned short random_rand(void);
```

**Best Practice:** If your MCU has a hardware RNG, use it for better entropy. Otherwise, seed from radio noise or other unpredictable sources.

#### SPI HAL - 📘 **Recommended** (if using external radio or peripherals)

**API** (from [`os/dev/spi.h`](https://github.com/contiki-ng/contiki-ng/blob/develop/os/dev/spi.h)):

Provides standardized SPI bus access for external devices (radios, sensors, storage).

**Your implementation provides:**
- Bus initialization and configuration
- Chip select management
- Data transfer functions
- Interrupt or DMA-based transfers (for efficiency)

#### DMA Support - 📘 Optional but valuable for performance

Direct Memory Access (DMA) can significantly improve performance for:
- UART transmit/receive
- SPI data transfers
- ADC sampling
- Radio packet transfers

**Implementation Considerations:**
- Configure DMA channels and priorities
- Handle DMA completion interrupts
- Manage cache coherency (if applicable)
- Provide DMA-safe buffer allocation
- Fall back to non-DMA operation if unavailable

**Example use case:** DMA-based UART reduces CPU overhead and improves throughput for serial communication.

#### Low-Power Modes - ⚠️ **Important for battery-powered devices**

Most embedded MCUs support multiple low-power modes (sleep, deep sleep, etc.).

**Implementation:**
- Identify available sleep modes on your MCU
- Implement mode selection in `platform_idle()` (see Platform Code section)
- Ensure peripherals can wake the system
- Handle clock reconfiguration after wake-up

**Sleep Mode Selection Strategy:**

```c
void platform_idle(void)
{
    /* Determine deepest sleep mode possible */
    if(rtimer_soon()) {
        /* Rtimer event soon - light sleep only */
        enter_light_sleep();
    } else if(etimer_pending()) {
        /* Etimer pending - can sleep until next event */
        enter_medium_sleep();
    } else {
        /* Nothing pending - deepest sleep */
        enter_deep_sleep();
    }
}
```

**Power Mode Comparison Example:**

| Mode | Current | Wake Sources | Wake Latency | Use Case |
|------|---------|-------------|--------------|----------|
| Active | 5 mA | N/A | N/A | Processing |
| Light Sleep | 500 µA | Any interrupt | <10 µs | Short idle |
| Deep Sleep | 50 µA | RTC, GPIO | <1 ms | Between packets |
| Shutdown | 1 µA | Reset, GPIO | >100 ms | Long-term storage |

#### I2C and ADC Drivers - 📘 Optional

**I2C:** For sensors and peripherals
- Implement master mode (slave rarely needed)
- Handle clock stretching
- Provide timeout mechanisms

**ADC:** For analog sensors
- Single-shot or continuous sampling
- Channel multiplexing
- Reference voltage configuration
- DMA integration for continuous sampling

---

## Platform Code

**Difficulty:** 📘 Moderate - Required for all ports

If you are reading this, your CPU is either already supported by Contiki-NG, or you have already added support as per the "[CPU code](#cpu-code)" section.

Let's assume your platform is called `my-platform` and it is powered by `my-new-mcu`.

**Initial Setup:**

1. Create directory: `arch/platform/my-platform/`
2. Create the following files:
   - `Makefile.my-platform` - Build system configuration
   - `platform.c` - Platform-specific initialization functions
   - `contiki-conf.h` - Platform configuration
   - `my-platform-def.h` (optional) - Non-modifiable platform definitions
   - `doxygen-group.txt` - Documentation structure

**Example `doxygen-group.txt`:**
```
/**
 * \defgroup my-platform My Platform
 * @{
 *
 * Documentation for My Platform
 */
```

See [`arch/platform/nrf/doxygen-group.txt`](https://github.com/contiki-ng/contiki-ng/tree/develop/arch/platform/nrf/doxygen-group.txt) for reference.

### Prepare the Configuration System

**Difficulty:** 📘 Moderate

The configuration system uses a carefully ordered include chain to allow user customization while maintaining system defaults.

**Configuration File Include Order:**

```
Project Makefile (DEFINES variable)
        ↓
project-conf.h (user's project-specific config)
        ↓
contiki-conf.h (platform configuration - YOU WRITE THIS)
        ↓
my-platform-def.h (platform defaults - non-modifiable)
        ↓
my-new-mcu-def.h (CPU defaults - non-modifiable)
        ↓
my-new-mcu-conf.h (CPU configuration - modifiable by user)
```

**Why this order matters:**

1. **User configuration first** - Project-specific settings have highest priority
2. **Platform defaults** - Platform provides sensible defaults
3. **CPU configuration last** - CPU-level settings that depend on platform configuration

**Edit `contiki-conf.h`:**

```c
#ifndef CONTIKI_CONF_H
#define CONTIKI_CONF_H

#include <stdint.h>
#include <inttypes.h>

/*---------------------------------------------------------------------------*/
/* Include Project Specific conf */
#ifdef PROJECT_CONF_PATH
#include PROJECT_CONF_PATH
#endif /* PROJECT_CONF_PATH */
/*---------------------------------------------------------------------------*/
/* Include platform and CPU default definitions BEFORE user configuration */
#include "my-platform-def.h"
#include "my-new-mcu-def.h"
/*---------------------------------------------------------------------------*/
/*
 * Platform-specific configuration options
 * Users can override these in project-conf.h
 */

/* Network configuration */
#ifndef NETSTACK_CONF_RADIO
#define NETSTACK_CONF_RADIO my_radio_driver
#endif

#ifndef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC tsch_driver
#endif

/* Platform features */
#ifndef PLATFORM_CONF_HAS_BUTTON
#define PLATFORM_CONF_HAS_BUTTON 1
#endif

#ifndef PLATFORM_CONF_HAS_LEDS
#define PLATFORM_CONF_HAS_LEDS 1
#endif

/* Logging configuration */
#ifndef LOG_CONF_LEVEL_MAIN
#define LOG_CONF_LEVEL_MAIN LOG_LEVEL_INFO
#endif

/*---------------------------------------------------------------------------*/
/* Include CPU-related configuration AFTER user configuration */
#include "my-new-mcu-conf.h"
/*---------------------------------------------------------------------------*/
#endif /* CONTIKI_CONF_H */
```

**Configuration Macro Naming Conventions:**

| Type | Pattern | Example | Location |
|------|---------|---------|----------|
| User-modifiable | `*_CONF_*` | `NETSTACK_CONF_MAC` | `contiki-conf.h` |
| Non-modifiable | `*_` (no CONF) | `CLOCK_SECOND` | `*-def.h` |
| Platform capability | `PLATFORM_CONF_HAS_*` | `PLATFORM_CONF_HAS_LEDS` | `contiki-conf.h` |
| Module-specific | `MODULE_CONF_*` | `TSCH_CONF_MAX_NODES` | `contiki-conf.h` |

**Best Practice:**
- Always use `#ifndef` guards to allow user override
- Document expected values and units in comments
- Group related configuration options together
- Provide sensible defaults

### Configure the Build System

**Difficulty:** 📘 Moderate

Edit `Makefile.my-platform` to configure the build system:

**Minimum required content:**

```Makefile
#### Platform-specific source files
CONTIKI_SOURCEFILES += platform.c leds-arch.c board-buttons.c

#### Clean target - remove platform firmware files
CLEAN += *.my-platform

#### Define CPU directory and include CPU Makefile
CONTIKI_CPU = $(CONTIKI)/arch/cpu/my-new-mcu
include $(CONTIKI_CPU)/Makefile.my-new-mcu

#### Add modules needed by this platform
# Example: External radio driver
MODULES += arch/dev/cc1200

# Example: External flash storage
MODULES += arch/dev/ext-flash

#### Platform-specific compiler flags (if needed)
CFLAGS += -DMY_PLATFORM_DEFINE

#### Board-specific Makefile inclusion
#### (Allows different board variants - see later section)
-include $(PLATFORM_ROOT_DIR)/$(BOARD)/Makefile.$(BOARD)

#### Useful targets for development
.PHONY: upload login

# Upload firmware to device (customize for your tools)
upload: $(CONTIKI_PROJECT).$(TARGET)
	my-flash-tool write $<

# Open serial console (customize for your setup)
login:
	screen /dev/ttyUSB0 115200
```

**Build System Variable Reference:**

| Variable | Purpose | Example |
|----------|---------|---------|
| `CONTIKI_SOURCEFILES` | Platform source files to compile | `platform.c leds-arch.c` |
| `MODULES` | Additional module directories to include | `arch/dev/cc1200` |
| `CLEAN` | Files to remove on `make clean` | `*.my-platform *.hex` |
| `CONTIKI_CPU` | Path to CPU directory | `$(CONTIKI)/arch/cpu/my-new-mcu` |
| `PLATFORM_ROOT_DIR` | Path to platform directory (predefined) | Used for board variants |
| `CFLAGS` | Additional compiler flags | `-DPLATFORM_FEATURE` |
| `LDFLAGS` | Additional linker flags | `-L./lib` |

**Common Makefile Targets:**

```Makefile
# Upload firmware via JTAG/SWD
upload: $(CONTIKI_PROJECT).$(TARGET)
	openocd -f interface/jlink.cfg -f target/my-mcu.cfg \
	        -c "program $< verify reset exit"

# Upload via serial bootloader
upload: $(CONTIKI_PROJECT).$(TARGET)
	my-bootloader-tool --port /dev/ttyUSB0 --write $<

# Open serial console
login:
	screen /dev/ttyUSB0 115200

# Open serial console (alternative)
login:
	picocom -b 115200 /dev/ttyUSB0

# List connected devices
motelist-all:
	ls -l /dev/ttyUSB*

# Create hex/bin files for flashing
%.hex: %.$(TARGET)
	$(OBJCOPY) -O ihex $< $@

%.bin: %.$(TARGET)
	$(OBJCOPY) -O binary $< $@
```

### Provide Startup, Main Loop and Low-Power Functions

**Difficulty:** 📘 Moderate - **Essential functions**

Contiki-NG provides a platform-independent `main()` routine in [`os/contiki-main.c`](https://github.com/contiki-ng/contiki-ng/tree/develop/os/contiki-main.c) that calls your platform-specific initialization functions.

**Required Functions (typically in `platform.c`):**

#### 1. `platform_init_stage_one()` - ⚠️⚠️ **Mandatory**

**Called:** Very early, before memory allocation or processes

**Purpose:** Absolute minimum initialization needed before anything else

**Typical contents:**
```c
void platform_init_stage_one(void)
{
    /* Disable watchdog if it starts enabled */
    watchdog_stop();

    /* Initialize clocks to known state (if not done in startup code) */
    /* Note: Detailed clock config usually in CPU code */

    /* Initialize GPIO direction registers for LEDs/buttons */
    /* (Actual LED/button drivers initialized later) */
}
```

**⚠️ Restrictions:**
- Do NOT use dynamic memory allocation
- Do NOT start processes
- Do NOT enable interrupts (if not already enabled)
- Keep this minimal - most init goes in stage two or three

#### 2. `platform_init_stage_two()` - ⚠️⚠️ **Mandatory**

**Called:** After memory allocation available, before autostart processes

**Purpose:** Main platform initialization

**Typical contents:**
```c
void platform_init_stage_two(void)
{
    /* Initialize LEDs */
    leds_init();
    leds_on(LEDS_RED);  /* Show we're booting */

    /* Initialize buttons */
    button_hal_init();

    /* Initialize sensors */
    SENSORS_ACTIVATE(temperature_sensor);

    /* Initialize radio hardware (but don't turn on yet) */
    /* Radio driver's init() will be called by netstack later */

    /* Platform-specific peripheral initialization */
    platform_uart_init();

    leds_off(LEDS_RED);
    leds_on(LEDS_GREEN);  /* Show we're ready */
}
```

**Can do:**
- Use dynamic memory allocation
- Initialize peripheral drivers
- Configure hardware

**Cannot do:**
- Start processes (not yet available)
- Assume network stack is initialized

#### 3. `platform_init_stage_three()` - ⚠️⚠️ **Mandatory**

**Called:** After autostart processes loaded, before entering main loop

**Purpose:** Final initialization that depends on processes being available

**Typical contents:**
```c
void platform_init_stage_three(void)
{
    /* Print platform information */
    printf("Platform: My Platform\n");
    printf("CPU: My New MCU @ %lu Hz\n", system_get_cpu_freq());

    /* Start platform-specific processes */
    process_start(&sensors_process, NULL);
    process_start(&serial_line_process, NULL);

    /* Enable interrupts that trigger process polls */
    uart_enable_rx_interrupt();
    button_enable_interrupts();

    /* Final LED indication */
    leds_off(LEDS_ALL);
}
```

**Can do:**
- Start processes
- Post events
- Enable interrupts
- Anything that requires full system initialization

#### 4. `platform_idle()` - ⚠️⚠️ **Mandatory**

**Called:** Repeatedly when system is idle

**Purpose:** Enter low-power mode to save energy

**Example implementation:**

```c
void platform_idle(void)
{
    /* Option 1: Simple implementation - just wait for interrupt */
    __WFI();  /* ARM Wait For Interrupt instruction */

    /* Option 2: Intelligent sleep mode selection */
    if(rtimer_arch_next() < RTIMER_NOW() + 100) {
        /* Rtimer event very soon - stay awake or light sleep */
        __WFI();
    } else if(etimer_pending()) {
        /* Etimer pending - medium sleep OK */
        enter_sleep_mode_2();
    } else {
        /* Nothing pending - deep sleep */
        enter_sleep_mode_3();
    }
}
```

**Power Management Strategy:**

The `platform_idle()` function is crucial for battery-powered devices. The main loop calls this repeatedly when no processes are ready to run.

**Sleep Mode Selection Flowchart:**

```
                platform_idle() called
                        │
                        ▼
        ┌───────────────────────────────┐
        │ Rtimer event in < 10µs?       │
        └───────┬───────────────┬───────┘
               Yes             No
                │               │
                ▼               ▼
          Stay awake    ┌──────────────────┐
                        │ UART TX active?  │
                        └─────┬──────┬─────┘
                             Yes    No
                              │      │
                              ▼      ▼
                        Light sleep  ┌──────────────┐
                        (CPU off,    │ Next event   │
                         peripherals │ > 100ms?     │
                         active)     └──┬────────┬──┘
                                       Yes      No
                                        │        │
                                        ▼        ▼
                                   Deep sleep  Medium sleep
                                   (Most off)  (Some periph)
```

**Common Sleep Modes:**

| Mode | Cortex-M | MSP430 | Current | Wake Latency | Use Case |
|------|----------|--------|---------|--------------|----------|
| Active | - | AM | ~5 mA | - | Processing |
| WFI | WFI | LPM0 | ~500 µA | <1 µs | Brief idle |
| Sleep | SLEEP | LPM1 | ~200 µA | <10 µs | Between events |
| Deep Sleep | DEEPSLEEP | LPM3 | ~5 µA | <1 ms | Long idle |
| Shutdown | SHUTDOWN | LPM4 | ~1 µA | >100 ms | Storage |

#### 5. `platform_main_loop()` - 📘 Optional

**Only needed if:** You require custom main loop behavior

**Default behavior:** If not provided, Contiki-NG uses this main loop:

```c
while(1) {
    while(process_run() > 0);  /* Run all ready processes */
    platform_idle();            /* Enter low-power mode */
}
```

**When to provide custom main loop:**
- Integration with RTOS
- Special power management requirements
- Hardware constraints requiring specific sequencing
- Native platform (POSIX) needs select() integration

**To provide custom loop:**

1. Implement `platform_main_loop()` in `platform.c`
2. Add to `my-platform-def.h`:
```c
#define PLATFORM_CONF_PROVIDES_MAIN_LOOP 1
```

**Example** (from native platform):
```c
void platform_main_loop(void)
{
    while(1) {
        fd_set fds;
        int n;
        struct timeval tv;

        /* Run processes */
        n = process_run();

        /* If nothing to do, wait for I/O or timer */
        if(n == 0) {
            tv = select_set_timeout(&fds);
            select(max_fd + 1, &fds, NULL, NULL, &tv);
        }
    }
}
```

See [`arch/platform/native/platform.c`](https://github.com/contiki-ng/contiki-ng/tree/develop/arch/platform/native/platform.c) for complete example.

### Develop Platform Drivers

**Difficulty:** 📘 Easy to Moderate

Implement drivers for off-chip peripherals:

#### LEDs (leds-arch.c) - 📘 **Recommended**

**API** (from [`os/dev/leds.h`](https://github.com/contiki-ng/contiki-ng/tree/develop/os/dev/leds.h)):

```c
void leds_arch_init(void);
leds_mask_t leds_arch_get(void);
void leds_arch_set(leds_mask_t leds);
```

**Configuration in `my-platform-def.h`:**

```c
/* Define available LEDs */
#define LEDS_CONF_RED    1
#define LEDS_CONF_GREEN  2
#define LEDS_CONF_BLUE   4
#define LEDS_CONF_YELLOW 8

#define LEDS_CONF_ALL (LEDS_CONF_RED | LEDS_CONF_GREEN | \
                       LEDS_CONF_BLUE | LEDS_CONF_YELLOW)

/* Map LEDs to GPIO pins (in leds-arch.c) */
#define LED_RED_PORT    GPIO_PORT_A
#define LED_RED_PIN     5
/* ... etc ... */
```

**Example implementation:**

```c
void leds_arch_init(void)
{
    /* Configure LED pins as outputs */
    GPIO_SET_OUTPUT(LED_RED_PORT, LED_RED_PIN);
    GPIO_SET_OUTPUT(LED_GREEN_PORT, LED_GREEN_PIN);

    /* Turn all LEDs off initially */
    leds_arch_set(0);
}

leds_mask_t leds_arch_get(void)
{
    leds_mask_t mask = 0;

    if(GPIO_READ_PIN(LED_RED_PORT, LED_RED_PIN)) {
        mask |= LEDS_CONF_RED;
    }
    /* ... check other LEDs ... */

    return mask;
}

void leds_arch_set(leds_mask_t leds)
{
    /* Set LED states based on mask */
    GPIO_WRITE_PIN(LED_RED_PORT, LED_RED_PIN,
                   (leds & LEDS_CONF_RED) ? 1 : 0);
    GPIO_WRITE_PIN(LED_GREEN_PORT, LED_GREEN_PIN,
                   (leds & LEDS_CONF_GREEN) ? 1 : 0);
    /* ... set other LEDs ... */
}
```

#### Buttons (board-buttons.c) - 📘 **Recommended**

**API** (from [`os/dev/button-hal.h`](https://github.com/contiki-ng/contiki-ng/blob/develop/os/dev/button-hal.h)):

The button HAL uses a registration system. You define button configurations and register them.

**Example implementation:**

```c
#include "dev/button-hal.h"

/* Button state structures */
button_hal_button_t button_user = {
    .next = NULL,
    .pin = BOARD_BUTTON_USER_PIN,
    .port = BOARD_BUTTON_USER_PORT,
    .pull = GPIO_HAL_PIN_CFG_PULL_UP,
    .negative_logic = true
};

button_hal_button_t button_reset = {
    .next = NULL,
    .pin = BOARD_BUTTON_RESET_PIN,
    .port = BOARD_BUTTON_RESET_PORT,
    .pull = GPIO_HAL_PIN_CFG_PULL_UP,
    .negative_logic = true
};

BUTTON_HAL_BUTTONS(&button_user, &button_reset);

void board_buttons_init(void)
{
    /* Configure button pins */
    gpio_hal_arch_pin_cfg_set(button_user.port, button_user.pin,
                              GPIO_HAL_PIN_CFG_INPUT | button_user.pull);
    gpio_hal_arch_interrupt_enable(button_user.port, button_user.pin);

    /* ... configure other buttons ... */
}

/* GPIO interrupt handler */
void gpio_button_isr(void)
{
    /* Notify button HAL of press */
    button_hal_notify_press(&button_user);

    /* Clear interrupt */
    gpio_hal_arch_clear_interrupt(button_user.port, button_user.pin);
}
```

**User code can then use buttons:**

```c
#include "dev/button-hal.h"

PROCESS_THREAD(my_process, ev, data)
{
    PROCESS_BEGIN();

    while(1) {
        PROCESS_WAIT_EVENT();

        if(ev == button_hal_press_event) {
            button_hal_button_t *btn = (button_hal_button_t *)data;
            printf("Button on pin %d pressed!\n", btn->pin);
        }
    }

    PROCESS_END();
}
```

#### Sensors - 📘 Optional

For platform-specific sensors, implement the sensor API.

**Common sensor types:**
- Temperature
- Humidity
- Light
- Accelerometer
- Battery voltage

**Example sensor driver structure:**

```c
#include "lib/sensors.h"

static int sensor_value(int type);
static int sensor_configure(int type, int value);
static int sensor_status(int type);

const struct sensors_sensor temperature_sensor = {
    "Temperature",
    sensor_value,
    sensor_configure,
    sensor_status
};

SENSORS_SENSOR(temperature_sensor, TEMPERATURE_SENSOR, sensor_value,
               sensor_configure, sensor_status);
```

#### External Storage - 📘 Optional

For SPI flash or similar external storage.

Consider using the generic driver in [`arch/dev/ext-flash`](https://github.com/contiki-ng/contiki-ng/tree/develop/arch/dev/ext-flash) - it may work with your hardware with minimal configuration.

**If implementing custom storage:**
- Implement read/write/erase functions
- Handle wear leveling if needed
- Consider integration with Coffee file system

#### Displays - 📘 Optional

For LCD or OLED displays:
- Define display initialization
- Implement text/graphics output functions
- Consider buffering strategies
- Handle SPI/I2C communication

### Add Support for Similar Board Variants

**Difficulty:** 📘 Moderate

When you have multiple similar boards sharing the same CPU and most peripherals, use the BOARD variant system.

**Scenario Example:**

Two similar devices based on `my-platform`:
- `usb-board`: Has USB connector, meant for border router use
- `sensing-board`: No USB, but has additional sensors and battery

**Both share:**
- Same CPU (`my-new-mcu`)
- Same LEDs and buttons
- Same basic configuration

**Differences:**
- `usb-board`: USB driver, USB-related examples
- `sensing-board`: Sensor drivers, battery monitoring

**Directory Structure:**

```
arch/platform/my-platform/
├── Makefile.my-platform          # Main platform Makefile
├── contiki-conf.h                 # Main configuration
├── platform.c                     # Common platform code
├── leds-arch.c                    # Common LED driver
├── board-buttons.c                # Common button driver
├── usb-board/                     # USB board variant
│   ├── Makefile.usb-board
│   ├── board.h                    # Board-specific config
│   └── usb-driver.c               # USB-specific driver
└── sensing-board/                 # Sensing board variant
    ├── Makefile.sensing-board
    ├── board.h                    # Board-specific config
    ├── temp-sensor.c              # Sensor driver
    └── battery-monitor.c          # Battery driver
```

**Step 1: Edit main platform Makefile**

Add to `Makefile.my-platform`:

```Makefile
#### Include the board-specific Makefile if one exists
-include $(PLATFORM_ROOT_DIR)/$(BOARD)/Makefile.$(BOARD)
```

The `-` prefix means "don't error if file doesn't exist" - allows building with default board.

**Step 2: Create board-specific Makefiles**

**`usb-board/Makefile.usb-board`:**
```Makefile
#### USB board specific sources
BOARD_SOURCEFILES += usb-driver.c

#### USB board specific modules
MODULES += os/services/slip-radio

#### Board-specific defines
CFLAGS += -DBOARD_HAS_USB=1
```

**`sensing-board/Makefile.sensing-board`:**
```Makefile
#### Sensing board specific sources
BOARD_SOURCEFILES += temp-sensor.c battery-monitor.c

#### Sensing board modules
MODULES += os/services/ipso-objects

#### Board-specific defines
CFLAGS += -DBOARD_HAS_BATTERY=1
```

**Step 3: Add board sourcefiles to main Makefile**

In `Makefile.my-platform`:
```Makefile
CONTIKI_SOURCEFILES += platform.c leds-arch.c board-buttons.c
CONTIKI_SOURCEFILES += $(BOARD_SOURCEFILES)  # Added by board Makefile
```

**Step 4: Create board-specific headers (optional)**

Each board can have a `board.h` that defines board-specific parameters:

**`usb-board/board.h`:**
```c
#ifndef BOARD_USB_BOARD_H
#define BOARD_USB_BOARD_H

#define BOARD_STRING "My Platform USB Board"

#define BOARD_HAS_USB 1

#define USB_VENDOR_ID  0x1234
#define USB_PRODUCT_ID 0x5678

#endif /* BOARD_USB_BOARD_H */
```

**Include in platform configuration:**

In `contiki-conf.h`:
```c
/* Include board-specific configuration if it exists */
#if defined(BOARD_CONF_PATH)
#include BOARD_CONF_PATH
#elif defined(BOARD)
#define BOARD_HEADER_STRING(x) #x "/ board.h"
#define BOARD_HEADER(x) BOARD_HEADER_STRING(x)
#include BOARD_HEADER(BOARD)
#endif
```

**Step 5: Building for different boards**

```bash
# Build for USB board
make TARGET=my-platform BOARD=usb-board

# Build for sensing board
make TARGET=my-platform BOARD=sensing-board

# Build for default board (no board-specific files)
make TARGET=my-platform
```

**Step 6: Save board selection**

Users can save their board choice:

```bash
make TARGET=my-platform BOARD=usb-board savetarget
```

This creates `Makefile.target` with saved settings.

**Alternative: Common Directory Approach**

For platforms with many boards sharing various combinations of peripherals:

```
arch/platform/my-platform/
├── Makefile.my-platform
├── platform.c
├── common/                        # Shared peripheral drivers
│   ├── temp-sensor.c
│   ├── humidity-sensor.c
│   ├── light-sensor.c
│   ├── battery-monitor.c
│   └── external-flash.c
├── board-a/
│   └── Makefile.board-a          # Includes temp + light
├── board-b/
│   └── Makefile.board-b          # Includes temp + humidity + flash
└── board-c/
    └── Makefile.board-c          # Includes all sensors
```

**`board-a/Makefile.board-a`:**
```Makefile
BOARD_SOURCEFILES += ../common/temp-sensor.c
BOARD_SOURCEFILES += ../common/light-sensor.c
```

**`board-b/Makefile.board-b`:**
```Makefile
BOARD_SOURCEFILES += ../common/temp-sensor.c
BOARD_SOURCEFILES += ../common/humidity-sensor.c
BOARD_SOURCEFILES += ../common/external-flash.c
```

See [`arch/platform/cc26x0-cc13x0`](https://github.com/contiki-ng/contiki-ng/tree/develop/arch/platform/cc26x0-cc13x0) for a real-world example.

---

## Testing and Validation

### Driver Development Progression Path

**Difficulty:** 📘 Easy to Moderate

Follow this recommended order for implementing and testing drivers:

#### Phase 1: Minimal Boot ✓ **Essential**

**Goal:** Get basic firmware running with debug output

**Checklist:**
- [ ] Linker script and startup code working
- [ ] Basic CPU initialization (clocks, memory)
- [ ] `platform_init_stage_*()` functions implemented
- [ ] Software clock (clock.c) working
- [ ] Rtimer (rtimer-arch.c) working
- [ ] UART output / printf working
- [ ] `hello-world` example runs and prints output

**Test with:**
```bash
cd examples/hello-world
make TARGET=my-platform
# Upload and verify output
make TARGET=my-platform upload
make TARGET=my-platform login
```

**Expected output:**
```
Hello, world
```

**Troubleshooting this phase:**
- No output? Check UART initialization, baud rate, pin configuration
- Garbled output? Check clock configuration, baud rate calculation
- Crashes immediately? Check linker script, stack size, startup code

#### Phase 2: Timers and Events ✓ **Essential**

**Goal:** Verify timer infrastructure and process system

**Checklist:**
- [ ] Etimers work correctly
- [ ] Ctimers work correctly
- [ ] Rtimers work correctly
- [ ] Process scheduling works
- [ ] Timer resolution and accuracy verified

**Test with a timer test example:**

Create `test-timers.c`:
```c
#include "contiki.h"
#include "sys/etimer.h"
#include "sys/rtimer.h"
#include <stdio.h>

PROCESS(test_process, "Timer test");
AUTOSTART_PROCESSES(&test_process);

static struct etimer et;
static rtimer_clock_t start_time;

PROCESS_THREAD(test_process, ev, data)
{
    PROCESS_BEGIN();

    printf("Testing etimers...\n");
    etimer_set(&et, CLOCK_SECOND);
    start_time = RTIMER_NOW();

    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

    rtimer_clock_t elapsed = RTIMER_NOW() - start_time;
    printf("Etimer: requested 1s, actual: %lu rtimer ticks\n",
           (unsigned long)elapsed);
    printf("Expected ~%lu ticks\n", (unsigned long)RTIMER_SECOND);

    PROCESS_END();
}
```

**Expected behavior:**
- Output should show elapsed time close to requested time
- Repeated tests should show consistent timing

#### Phase 3: Interrupts and Input ✓ **Recommended**

**Goal:** Verify interrupt handling and input capabilities

**Checklist:**
- [ ] Global interrupt enable/disable working
- [ ] Interrupt handlers properly implemented
- [ ] Button interrupts working
- [ ] Serial line input working
- [ ] No interrupt-related crashes or hangs

**Test with button example:**

```c
#include "contiki.h"
#include "dev/button-hal.h"
#include <stdio.h>

PROCESS(button_test_process, "Button test");
AUTOSTART_PROCESSES(&button_test_process);

PROCESS_THREAD(button_test_process, ev, data)
{
    PROCESS_BEGIN();

    printf("Press buttons...\n");

    while(1) {
        PROCESS_WAIT_EVENT();

        if(ev == button_hal_press_event) {
            button_hal_button_t *btn = data;
            printf("Button pressed: pin %d\n", btn->pin);
        } else if(ev == button_hal_release_event) {
            button_hal_button_t *btn = data;
            printf("Button released: pin %d\n", btn->pin);
        }
    }

    PROCESS_END();
}
```

**Test serial input with shell:**
```bash
cd examples/libs/shell
make TARGET=my-platform
# Upload and connect terminal
# Type "help" - should see shell commands
```

#### Phase 4: Networking (if applicable) ⚠️ **Complex**

**Goal:** Basic networking functionality

**Checklist:**
- [ ] Radio driver initialized correctly
- [ ] Can send packets
- [ ] Can receive packets
- [ ] Basic IPv6 connectivity
- [ ] MAC layer working (CSMA, TSCH, etc.)

**Test with nullnet broadcast:**

```bash
cd examples/nullnet
make TARGET=my-platform nullnet-broadcast
# Upload to multiple devices
# Should see packets being received
```

**Test with ping:**

```bash
cd examples/rpl-udp
make TARGET=my-platform
# Upload udp-client and udp-server to different nodes
# Should see UDP communication
```

#### Phase 5: Advanced Features 📘 **Optional**

**Checklist:**
- [ ] Low-power modes working
- [ ] Current consumption meets expectations
- [ ] Sensors reading correctly
- [ ] External storage working
- [ ] All peripherals functional

**Performance Testing:**

Create benchmarks to verify:
- Timer accuracy over long periods
- Radio throughput and reliability
- Power consumption in various modes
- Flash/RAM usage

**Stress Testing:**

- Run for extended periods (hours/days)
- High packet rate scenarios
- Interrupt-heavy workloads
- Ensure no memory leaks or crashes

### Create Examples

**Difficulty:** 📘 Easy to Moderate

#### Platform-Independent Examples

**Goal:** Make existing examples work on your platform

**Best Practice:** ⚠️ **Do NOT duplicate entire examples** - extend them instead!

**Approach 1: Examples that work out-of-the-box**

Test these common examples on your platform:
- `hello-world`
- `nullnet` examples
- `rpl-udp`
- `mqtt-client`
- `coap` examples

If they compile and run without modification, you're done!

**Approach 2: Platform-specific extensions**

Some examples benefit from platform-specific extensions while remaining platform-independent.

**Example:** The MQTT client example allows platform-specific sensor readings.

See [`examples/mqtt-client`](https://github.com/contiki-ng/contiki-ng/tree/develop/examples/mqtt-client) - it includes optional platform-specific code through conditional compilation:

```c
#if PLATFORM_SUPPORTS_BUTTON_HAL
#include "dev/button-hal.h"
#endif

/* Later in code */
#if PLATFORM_SUPPORTS_BUTTON_HAL
    if(ev == button_hal_press_event) {
        /* Handle button for MQTT trigger */
    }
#endif
```

**To extend an example for your platform:**

1. Check if the example supports platform extensions
2. Add your platform-specific code conditionally
3. Test on other platforms to ensure no breakage

**Approach 3: Project-specific configuration**

Create a `project-conf.h` in the example directory for platform-specific settings:

```c
/* project-conf.h for rpl-border-router on my-platform */
#if CONTIKI_TARGET_MY_PLATFORM

/* Use TSCH */
#define MAC_CONF_WITH_TSCH 1

/* Platform has UART1 for serial output */
#define UART_CONF_ENABLE 1

/* Increase buffer sizes for border router */
#define UIP_CONF_BUFFER_SIZE 1280

#endif /* CONTIKI_TARGET_MY_PLATFORM */
```

#### Platform-Specific Examples

**Goal:** Showcase your platform's unique features

Create examples under `examples/platform-specific/my-platform/`:

```
examples/platform-specific/my-platform/
├── basic-demo/
│   ├── Makefile
│   ├── README.md
│   ├── basic-demo.c
│   └── project-conf.h
├── sensor-demo/
│   ├── Makefile
│   ├── README.md
│   └── sensor-demo.c
└── advanced-networking/
    ├── Makefile
    ├── README.md
    └── advanced-demo.c
```

**Example Makefile:**

```Makefile
CONTIKI_PROJECT = basic-demo
all: $(CONTIKI_PROJECT)

# Platform must be my-platform for this example
PLATFORMS_ONLY = my-platform

CONTIKI = ../../../..
include $(CONTIKI)/Makefile.include
```

**Example README.md:**

```markdown
# My Platform Basic Demo

This example demonstrates the basic features of My Platform:
- LED control
- Button input
- Sensor readings
- Serial output

## Hardware Requirements
- My Platform board (usb-board or sensing-board variant)
- USB cable for programming and serial

## Usage

1. Build:
   ```
   make TARGET=my-platform BOARD=usb-board
   ```

2. Upload:
   ```
   make TARGET=my-platform BOARD=usb-board upload
   ```

3. View output:
   ```
   make TARGET=my-platform login
   ```

## Expected Output
```
My Platform Basic Demo
Press button to read sensor...
```

**Good Platform-Specific Example Ideas:**

- **Basic demo**: LEDs, buttons, sensors, serial
- **Networking demo**: Border router setup, multi-hop network
- **Sensor logging**: Periodic sensor readings with storage
- **Low-power demo**: Demonstrate sleep modes and current consumption
- **Web interface**: HTTP server showing sensor data
- **Actuator control**: Control motors, relays, etc.

**Reference Examples:**

Look at existing platform-specific examples for inspiration:
- [`examples/platform-specific/cc26x0-cc13x0`](https://github.com/contiki-ng/contiki-ng/tree/develop/examples/platform-specific/cc26x0-cc13x0)
- [`examples/platform-specific/nrf`](https://github.com/contiki-ng/contiki-ng/tree/develop/examples/platform-specific/nrf)
- [`examples/platform-specific/zoul`](https://github.com/contiki-ng/contiki-ng/tree/develop/examples/platform-specific/zoul)

### Add CI Tests

**Difficulty:** 📘 Easy

Add compile tests to ensure your platform builds correctly in continuous integration.

**Goal:** Automatically test that key examples compile for your platform

**CI Test Structure:**

Contiki-NG's CI includes multiple test jobs:
- `tests/01-compile-base/` - Core examples
- `tests/02-compile-arm-ports-01/` - ARM platform tests
- `tests/02-compile-arm-ports-02/` - More ARM tests
- etc.

**Choose appropriate test Makefile** and add your platform's tests.

**Example Scenario:**

Your platform `my-platform` has two boards: `board-a` (default) and `board-b`.

You want to test:
- `hello-world` and `rpl-udp` for `board-a` (default)
- `rpl-border-router` and `sensniff` for `board-b` only
- Your platform-specific examples for both boards

**Edit** `tests/01-compile-base/Makefile` (or appropriate test file):

```Makefile
# Add to the EXAMPLES variable (around line 20-100)

EXAMPLES += \
  hello-world/my-platform \
  rpl-udp/my-platform \
  rpl-border-router/my-platform:BOARD=board-b \
  sensniff/my-platform:BOARD=board-b \
  platform-specific/my-platform/basic-demo/my-platform:BOARD=board-a \
  platform-specific/my-platform/basic-demo/my-platform:BOARD=board-b \
  platform-specific/my-platform/sensor-demo/my-platform:BOARD=board-a \
  platform-specific/my-platform/sensor-demo/my-platform:BOARD=board-b \
```

**Format:**
```
<example-path>/<target>[:BOARD=<board>][:OTHER_VAR=value]
```

**Tips:**
- Don't test every example - choose representative ones
- Test different boards if they have different features
- Include at least one networking example
- Include your platform-specific examples
- Test should complete in reasonable time (CI limits)

**Testing Locally:**

Before committing, test your changes:

```bash
cd tests/01-compile-base
make
```

This will compile all examples in that test file, including your new ones.

**Coverage Guidelines:**

Aim to test:
- [ ] At least one basic example (hello-world)
- [ ] At least one networking example (rpl-udp, etc.)
- [ ] Platform-specific examples (all of them)
- [ ] Different boards if features differ significantly
- [ ] Any examples that use platform-unique features

**Don't test:**
- Every possible example (wastes CI resources)
- Examples that are identical in functionality
- Boards that are truly identical in build

---

## Documentation

**Difficulty:** 📘 Easy - **Required for upstreaming**

If you plan to contribute your port to Contiki-NG, documentation is mandatory.

### API Documentation (Doxygen)

**Goal:** Document all public functions, types, and configuration

**Minimum Requirements:**

1. **File headers:**

```c
/**
 * \addtogroup my-platform
 * @{
 *
 * \file
 *         Platform initialization for My Platform
 * \author
 *         Your Name <your.email@example.com>
 */
```

2. **Function documentation:**

```c
/**
 * \brief Initialize the temperature sensor
 * \param mode Sensor mode: 0 = low power, 1 = high accuracy
 * \return 0 on success, -1 on failure
 *
 * This function initializes the temperature sensor and puts it in the
 * specified mode. In low-power mode, the sensor consumes ~1µA but has
 * ±2°C accuracy. In high-accuracy mode, consumption is ~100µA with
 * ±0.5°C accuracy.
 *
 * \note The sensor requires at least 100ms to stabilize after init
 */
int temperature_sensor_init(int mode);
```

3. **Configuration documentation:**

In header files:

```c
/**
 * \name My Platform Configuration
 * @{
 */

/**
 * \brief Number of LEDs on the board
 *
 * Set to the number of controllable LEDs. Used by the LED HAL.
 */
#ifdef MY_PLATFORM_CONF_LED_COUNT
#define MY_PLATFORM_LED_COUNT MY_PLATFORM_CONF_LED_COUNT
#else
#define MY_PLATFORM_LED_COUNT 4
#endif

/** @} */
```

4. **Close doxygen groups:**

At end of files:

```c
/**
 * @}
 */
```

### Platform README

Create `arch/platform/my-platform/README.md`:

```markdown
# My Platform

This directory contains the Contiki-NG port for My Platform, based on
the My New MCU microcontroller.

## Platform Features

- ARM Cortex-M4F @ 48 MHz
- 256 KB Flash, 64 KB RAM
- IEEE 802.15.4 radio @ 2.4 GHz
- USB 2.0 Full Speed
- Multiple low-power modes

## Supported Boards

### USB Board (`BOARD=usb-board`)
Development board with USB connector, suitable for border router applications.

### Sensing Board (`BOARD=sensing-board`)
Battery-powered board with additional sensors.

## Getting Started

### Prerequisites

Install the ARM GCC toolchain:
```bash
sudo apt-get install gcc-arm-none-eabi
```

### Building Examples

```bash
cd examples/hello-world
make TARGET=my-platform BOARD=usb-board
```

### Uploading Firmware

Connect your board via USB and run:
```bash
make TARGET=my-platform BOARD=usb-board upload
```

### Viewing Output

```bash
make TARGET=my-platform login
```

## Platform-Specific Examples

See `examples/platform-specific/my-platform/` for examples showcasing
platform features.

## Configuration

See `contiki-conf.h` for configuration options. Common options can be
overridden in your project's `project-conf.h`.

## Low-Power Operation

The platform supports multiple sleep modes. Current consumption:
- Active: ~5 mA
- Light sleep: ~500 µA
- Deep sleep: ~5 µA

## Maintainers

- Your Name <your.email@example.com>
- Collaborator Name <collab@example.com>

## References

- [My Platform Homepage](https://www.example.com/my-platform)
- [CPU Reference Manual](https://www.example.com/datasheet.pdf)
```

### Wiki Documentation

For upstream contributions, create a wiki page following the pattern of existing platform pages.

**Sections to include:**

1. **Overview** - Brief description, key features
2. **Hardware** - Specifications, available boards
3. **Getting Started** - Prerequisites, building, uploading
4. **Examples** - Links to working examples
5. **Configuration** - Important configuration options
6. **Known Issues** - Any limitations or workarounds
7. **Maintainers** - Contact information
8. **References** - Links to datasheets, vendor sites

**See existing platform pages:** [The Contiki-NG platforms][wiki-platforms]

### Example README Files

For each platform-specific example, include a README.md:

```markdown
# My Platform Basic Demo

Brief description of what this example demonstrates.

## Hardware Required

- My Platform USB Board
- USB cable

## Features Demonstrated

- LED control
- Button interrupt handling
- Sensor reading
- Serial output

## Building

```bash
make TARGET=my-platform BOARD=usb-board
```

## Running

Upload and view output:
```bash
make TARGET=my-platform upload login
```

## Expected Output

```
My Platform Basic Demo
Temperature: 23.5°C
Press button...
```

## Configuration

Key configuration options in `project-conf.h`:
- `SENSOR_READ_INTERVAL` - Reading interval in seconds
- `LED_BLINK_ON_READ` - Blink LED on sensor read

## License

This example code is in the public domain.
```

---

## Common Good Practices

### Observe the Code Style Convention

**Difficulty:** 📘 Easy - **Mandatory for upstream**

Contiki-NG uses Uncrustify for code formatting.

**Check your code style:**

```bash
./tools/code-style/uncrustify-check-style.sh arch/platform/my-platform/platform.c
```

**Fix code style:**

```bash
./tools/code-style/uncrustify-fix-style.sh arch/platform/my-platform/platform.c
```

**Fix all changed files:**

```bash
./tools/code-style/uncrustify-changed.sh
```

**Key Style Points:**

- **Indentation:** 2 spaces (no tabs)
- **Function names:** `lowercase_with_underscores`
- **Macros:** `UPPERCASE_WITH_UNDERSCORES`
- **Braces:** K&R style (opening brace on same line)
- **Line length:** Prefer ≤80 characters
- **Comments:** `/* C-style comments */` for code, `//` for temporary notes

**Example:**

```c
/* Good style */
void
my_function(int param)
{
  if(param > 0) {
    do_something();
  } else {
    do_something_else();
  }
}

/* Bad style */
void my_function( int param ){
    if( param > 0 )
    {
        do_something( );
    }
    else
    {
        do_something_else( );
    }
}
```

See [Code Style Guide][wiki-code-style] for complete details.

### Avoid Code Duplication

**Difficulty:** 📘 Moderate

**Principle:** DRY (Don't Repeat Yourself)

**Common scenarios:**

#### Scenario 1: Existing driver almost fits

**❌ Don't:** Copy entire driver and modify

**✅ Do:** Propose changes to make driver more flexible

**Example:** You need SPI flash driver but with different commands.

Instead of copying `arch/dev/ext-flash/ext-flash.c`, propose adding configuration options:

```c
/* In ext-flash.h */
#ifndef EXT_FLASH_CONF_ERASE_COMMAND
#define EXT_FLASH_ERASE_COMMAND 0x20
#else
#define EXT_FLASH_ERASE_COMMAND EXT_FLASH_CONF_ERASE_COMMAND
#endif
```

Then in your `contiki-conf.h`:
```c
#define EXT_FLASH_CONF_ERASE_COMMAND 0xD8  /* Your chip's erase command */
```

#### Scenario 2: Example needs slight platform modification

**❌ Don't:** Copy entire example to `platform-specific/`

**✅ Do:** Extend the example with conditional compilation

See how `mqtt-client` handles this:

```c
/* mqtt-client.c */
#ifdef PLATFORM_SUPPORTS_SENSORS
  read_sensors(&data);
#else
  /* Generic data */
  data = default_value;
#endif
```

#### Scenario 3: Multiple platforms need same code

**❌ Don't:** Copy to each platform

**✅ Do:** Create shared module

**Example:** Multiple ARM Cortex-M platforms need same USB code.

Put shared code in `arch/cpu/arm/common/usb/` and include from each platform:

```Makefile
# In each platform's Makefile
MODULES += arch/cpu/arm/common/usb
```

### Is it a CPU Thing or Platform Thing?

**Difficulty:** 📘 Moderate - **Important for maintainability**

**Decision Tree:**

```
Is this code related to something inside the main chip?
    ├─ Yes → CPU directory (arch/cpu/)
    │   Examples:
    │   - CPU clock configuration
    │   - On-chip peripherals (UART, SPI, I2C controllers)
    │   - On-chip radio
    │   - Memory management
    │   - Interrupt controller
    │   - DMA controller
    │
    └─ No → Platform directory (arch/platform/)
        Examples:
        - LED connections
        - Button connections
        - External sensors
        - External radio (if not integrated)
        - External flash
        - Board-specific pin mappings
```

**Configuration follows the same rule:**

| Config Type | Location | Example |
|-------------|----------|---------|
| CPU-related | `my-new-mcu-conf.h` | `UART_CONF_BAUD_RATE` |
| Platform-related | `contiki-conf.h` | `NETSTACK_CONF_MAC` |
| Board-related | `board.h` | `BUTTON_USER_PIN` |

**Gray Areas:**

Some things could go either place:

**GPIO pin assignments:**
- **CPU header:** Define GPIO port/pin naming scheme
- **Platform header:** Define which pins are used for what

```c
/* my-new-mcu-def.h (CPU) */
#define GPIO_PORT_A 0
#define GPIO_PORT_B 1

/* my-platform-def.h (Platform) */
#define LED_RED_PORT GPIO_PORT_A
#define LED_RED_PIN 5
```

### Do Not Add Platform Code in Platform-Independent Files

**Difficulty:** 📘 Moderate

**❌ Anti-pattern:**

```c
/* In os/sys/some-module.c (platform-independent) */
static void
platform_independent_function(void)
{
  /* Do platform independent stuff */

#if CONTIKI_TARGET_MY_NEW_PLATFORM
  platform_foo_function();
#endif

  /* Do remaining platform independent stuff */
}
```

**Why this is bad:**
- Platform-independent code becomes cluttered
- Doesn't scale (imagine 50 platforms)
- Hard to maintain
- Defeats purpose of abstraction

**✅ Better approaches:**

#### Approach 1: Use callbacks/function pointers

```c
/* In os/sys/some-module.h */
struct module_driver {
  void (*init)(void);
  int (*process)(void);
};

extern const struct module_driver *module_driver_impl;
```

```c
/* In your platform code */
const struct module_driver my_platform_driver = {
  .init = my_init,
  .process = my_process
};

const struct module_driver *module_driver_impl = &my_platform_driver;
```

#### Approach 2: Use weak symbols (for simple cases)

```c
/* In os/sys/some-module.c */
void __attribute__((weak))
platform_specific_hook(void)
{
  /* Default implementation (does nothing) */
}

/* Platform code can override */
void platform_specific_hook(void)
{
  /* My platform's implementation */
}
```

#### Approach 3: Use configuration to select implementation

```c
/* In os/sys/some-module.c */
#if SOME_FEATURE_CONF_ENABLED
  some_feature_init();
#endif
```

```c
/* In your contiki-conf.h */
#define SOME_FEATURE_CONF_ENABLED 1
```

**When in doubt:** Ask on Gitter before adding platform-specific code to platform-independent files.

---

## Troubleshooting

**Difficulty:** Various

### No Serial Output

**Symptoms:** Device appears to boot but no printf output

**Checks:**

1. **Baud rate mismatch**
   ```c
   /* Check UART initialization */
   #define UART_CONF_BAUD_RATE 115200  /* Must match terminal */
   ```

2. **Wrong UART pins**
   - Verify TX/RX pin configuration
   - Check if pins are muxed correctly
   - Confirm pin direction (TX = output)

3. **Clock configuration wrong**
   - UART baud rate depends on correct clock
   - Verify system clock frequency
   - Check UART clock divider calculation

4. **putchar not linked**
   ```bash
   # Check if putchar is defined
   arm-none-eabi-nm firmware.elf | grep putchar
   ```

5. **Buffer not flushing**
   - Try adding `fflush(stdout)` after printf
   - Check if UART TX complete before sleeping

**Debug technique:**
```c
/* Toggle LED in known locations */
void platform_init_stage_one(void) {
    LED_INIT();  /* Initialize LED directly (not via HAL) */
    LED_ON();    /* If this lights, we're booting */
    /* ... rest of init ... */
    LED_OFF();   /* If this happens, init completed */
}
```

### Crashes Immediately After Boot

**Symptoms:** Device resets or hangs at startup

**Common Causes:**

1. **Stack overflow**
   - **Check:** Increase stack size in linker script
   - **Symptom:** Crash in random places, especially after function calls
   ```ld
   /* In linker script */
   _stack_size = 0x2000;  /* Try increasing this */
   ```

2. **Uninitialized .data section**
   - **Check:** Startup code copies .data from flash to RAM
   ```c
   /* In startup code */
   uint32_t *src = &_etext;
   uint32_t *dst = &_data;
   while(dst < &_edata) {
       *dst++ = *src++;  /* Must copy initialized data */
   }
   ```

3. **Uncleared .bss section**
   - **Check:** Startup code zeros .bss
   ```c
   /* In startup code */
   dst = &_bss;
   while(dst < &_ebss) {
       *dst++ = 0;  /* Must zero uninitialized data */
   }
   ```

4. **Wrong vector table location**
   - **Check:** Vector table at correct address
   - **ARM Cortex-M:** Usually 0x00000000, must be aligned

5. **Clock not initialized**
   - **Check:** System clock configured before any peripherals
   - **Symptom:** Watchdog timeout, peripherals don't respond

**Debug technique:**

Use debugger to check where it crashes:
```bash
arm-none-eabi-gdb firmware.elf
(gdb) target remote localhost:3333  # If using OpenOCD
(gdb) monitor reset halt
(gdb) continue
# Wait for crash
(gdb) backtrace  # See where it crashed
```

### Timers Don't Work Correctly

**Symptoms:** Timers too fast, too slow, or don't fire

**Checks:**

1. **CLOCK_CONF_SECOND wrong**
   ```c
   /* Must match actual interrupt rate */
   #define CLOCK_CONF_SECOND 128  /* Hz */
   ```

2. **Hardware timer misconfigured**
   - Check timer prescaler/divider
   - Verify timer clock source
   - Confirm interrupt rate calculation

3. **Interrupt not firing**
   - Enable timer interrupt in NVIC (ARM)
   - Clear interrupt flag in ISR
   - Check interrupt priority

4. **etimer_request_poll() not called**
   ```c
   /* In clock ISR */
   if(etimer_pending()) {
       etimer_request_poll();  /* MUST call this */
   }
   ```

**Test:**
```c
/* Verify clock accuracy */
void test_clock(void) {
    clock_time_t start = clock_time();
    clock_delay_usec(1000000);  /* Wait 1 second */
    clock_time_t elapsed = clock_time() - start;
    printf("Elapsed: %lu ticks (expected %d)\n",
           (unsigned long)elapsed, CLOCK_SECOND);
}
```

### Radio Doesn't Work

**Symptoms:** Can't send/receive packets

**Common Issues:**

1. **Radio not initialized**
   - Check radio driver `init()` called
   - Verify radio power enabled
   - Check SPI communication (if external radio)

2. **Wrong frequency/channel**
   - Verify channel configuration
   - Check frequency synthesizer settings

3. **TX power too low**
   - Increase TX power
   - Check antenna connection

4. **Radio timing issues (TSCH)**
   - Verify precise timestamping
   - Check rtimer accuracy
   - Confirm ACK timing

5. **Incorrect frame format**
   - Check 802.15.4 frame structure
   - Verify address filtering
   - Check FCS (frame check sequence)

**Debug:**
```c
/* Add logging to radio driver */
printf("Radio: TX %d bytes on channel %d\n", len, channel);
printf("Radio: RX %d bytes, RSSI %d\n", len, rssi);
```

### High Power Consumption

**Symptoms:** Battery drains faster than expected

**Checks:**

1. **Not entering sleep**
   - Verify `platform_idle()` implementation
   - Check if processes prevent sleep

2. **Peripherals stay on**
   - Turn off unused peripherals
   - Disable high-speed clocks when idle

3. **Radio left on**
   - Ensure radio duty cycling works
   - Check MAC layer power management

4. **LEDs consuming power**
   - Turn off LEDs in production builds
   - Use high-resistance LEDs

**Measurement:**
Use current measurement tool to profile:
- Active current
- Sleep current
- Current during radio TX/RX

### Build Errors

**Common build errors and solutions:**

#### "undefined reference to `main`"
- **Cause:** Linker can't find main()
- **Solution:** Include `os/contiki-main.c` in build

#### "multiple definition of `symbol`"
- **Cause:** Symbol defined in multiple files
- **Solution:** Make one definition `static` or remove duplicate

#### "No rule to make target"
- **Cause:** Source file not in CONTIKI_SOURCEFILES
- **Solution:** Add to Makefile

#### Implicit function declaration
- **Cause:** Missing #include
- **Solution:** Include appropriate header

### Memory Issues

**Symptoms:** Malloc fails, stack corruption

**Checks:**

1. **Insufficient heap**
   ```c
   /* Increase heap size in linker script */
   _heap_size = 0x4000;  /* 16KB heap */
   ```

2. **Stack overflow**
   - Increase stack size
   - Reduce local variable usage
   - Check recursive functions

3. **Memory leaks**
   - Ensure all `malloc()` have matching `free()`
   - Use static allocation where possible

**Debug:**
```c
/* Check available memory */
extern uint32_t _heap_start;
extern uint32_t _heap_end;
printf("Heap: %lu bytes\n",
       (unsigned long)(&_heap_end - &_heap_start));
```

---

## Examples of Successful Ports

**Reference these when porting:**

| Platform | CPU Family | Complexity | Key Features | Reference |
|----------|-----------|------------|--------------|-----------|
| [Native](https://github.com/contiki-ng/contiki-ng/tree/develop/arch/platform/native) | POSIX | Moderate | Custom main loop, select() integration | Good for understanding main loop |
| [CC2538](https://github.com/contiki-ng/contiki-ng/tree/develop/arch/cpu/cc2538) | ARM Cortex-M3 | Advanced | Integrated radio, USB, comprehensive | Full-featured reference |
| [nRF52840](https://github.com/contiki-ng/contiki-ng/tree/develop/arch/platform/nrf) | ARM Cortex-M4F | Advanced | BLE radio, USB, multiple boards | Modern ARM example |
| [CC26xx/CC13xx](https://github.com/contiki-ng/contiki-ng/tree/develop/arch/platform/cc26x0-cc13x0) | ARM Cortex-M3 | Advanced | Multiple boards, common drivers | Board variant example |
| [Zoul](https://github.com/contiki-ng/contiki-ng/tree/develop/arch/platform/zoul) | CC2538 | Moderate | Multiple board variants, external radio | Platform variants |
| [OpenMote](https://github.com/contiki-ng/contiki-ng/tree/develop/arch/platform/openmote) | CC2538 | Moderate | Clean structure, good documentation | Simple, clear example |

**What to learn from each:**

- **Native**: Custom main loop, signal handling, file I/O
- **CC2538**: Comprehensive CPU port, TSCH support, crypto
- **nRF52840**: Modern ARM Cortex-M4F, BLE integration
- **CC26xx**: Board variant management with common drivers
- **Zoul**: Simple board variants, external peripherals
- **OpenMote**: Clean code structure, good starting point

---

## Support

**Getting Help:**

1. **Gitter Chat:** [Developers Room](https://gitter.im/contiki-ng)
   - Ask porting questions
   - Get advice from maintainers
   - Discuss design decisions

2. **GitHub Discussions:** [Contiki-NG Discussions](https://github.com/contiki-ng/contiki-ng/discussions)
   - Longer-form questions
   - Design discussions
   - Feature requests

3. **GitHub Issues:** [Report Bugs](https://github.com/contiki-ng/contiki-ng/issues)
   - Bug reports
   - Build system issues
   - Documentation errors

**Before asking:**
- Read this guide thoroughly
- Check existing platform implementations
- Search for similar questions
- Prepare a minimal reproducible example

**When asking for help, include:**
- Your MCU/platform details
- Build output or error messages
- Relevant code snippets
- What you've already tried

**Contributing Your Port:**

Once your port is working, consider contributing it upstream!

See [Contributing Guidelines][wiki-contributing] for:
- Code review process
- Pull request requirements
- Maintainer expectations
- License requirements

---

## Quick Reference: File Checklist

Use this checklist to ensure you've created all necessary files:

### CPU Port Files
```
arch/cpu/my-new-mcu/
├── Makefile.my-new-mcu          ✓ Build configuration
├── my-new-mcu.ld                ✓ Linker script
├── my-new-mcu-def.h             ✓ Non-modifiable definitions
├── my-new-mcu-conf.h            ✓ User configuration
├── doxygen-group.txt            ✓ Documentation structure
├── startup-my-new-mcu.c         ✓ Startup code
├── clock.c                      ✓ Software clock
├── rtimer-arch.c                ✓ Rtimer implementation
├── rtimer-arch.h
├── uart.c                       ✓ UART driver
├── watchdog.c                   ✓ Watchdog driver
├── gpio-hal-arch.c              ○ GPIO HAL (recommended)
├── gpio-hal-arch.h
├── int-master.c (or in .h)      ✓ Interrupt management
├── radio.c                      ○ Radio driver (if on-chip)
├── radio.h
└── README.md                    ○ CPU documentation

Legend: ✓ = Required, ○ = Recommended, □ = Optional
```

### Platform Port Files
```
arch/platform/my-platform/
├── Makefile.my-platform         ✓ Build configuration
├── contiki-conf.h               ✓ Platform configuration
├── my-platform-def.h            ○ Platform definitions
├── doxygen-group.txt            ✓ Documentation structure
├── platform.c                   ✓ Initialization functions
├── leds-arch.c                  ○ LED driver
├── board-buttons.c              ○ Button driver
├── sensors/                     □ Sensor drivers
│   ├── temperature-sensor.c
│   └── ...
├── board-a/                     □ Board variant A
│   ├── Makefile.board-a
│   └── board.h
├── board-b/                     □ Board variant B
│   ├── Makefile.board-b
│   └── board.h
└── README.md                    ✓ Platform documentation
```

### Example Files
```
examples/platform-specific/my-platform/
├── basic-demo/
│   ├── Makefile                 ✓ Build configuration
│   ├── README.md                ✓ Usage instructions
│   ├── basic-demo.c             ✓ Example code
│   └── project-conf.h           ○ Project configuration
└── ...
```

### Test Files
```
tests/01-compile-base/Makefile   ✓ Add compile tests
tests/02-.../Makefile            ○ Additional tests
```

---

**You've reached the end of the porting guide! 🎉**

This guide should have equipped you with everything needed to port Contiki-NG to your platform. Remember:

- Start simple (minimal boot first)
- Test incrementally
- Reuse existing code where possible
- Ask for help when stuck
- Document your work
- Consider contributing back

Good luck with your port!

[tutorial:hello-world]: /doc/tutorials/Hello,-World!
[tutorial:shell]: /doc/tutorials/Shell
[wiki-platforms]: /doc/platforms/index.rst
[wiki-code-style]: /doc/project/Code-style
[wiki-contributing]: /doc/project/Contributing
[doc:tsch]: TSCH-and-6TiSCH.md#porting-tsch-to-a-new-platform
[doc:build-system]: /doc/getting-started/The-Contiki-NG-build-system
[doc:multitasking-and-scheduling]: Multitasking-and-scheduling.md#writing-interrupt-handlers
