# Fuzzing the network stack

This directory fuzzes the input paths of the Contiki-NG network stack with
[AFL++](https://github.com/AFLplusplus/AFLplusplus), which is actively
maintained and packaged for Linux, macOS and the BSDs.

Nothing here runs in continuous integration. A fuzzing campaign is not a
regression test, and is meant to be run deliberately.

## Running a campaign

    ./fuzz.sh <target> [duration]

The duration accepts a plain number of seconds, or a number followed by `s`,
`m` or `h`, and defaults to ten minutes:

    ./fuzz.sh rpl-icmpv6            # ten minutes
    ./fuzz.sh rpl-icmpv6 30s        # long enough to check that it works
    ./fuzz.sh snmp 24h              # long enough to expect a result

Run `./fuzz.sh` with no arguments to list the available targets. Results are
written to `out/<target>`.

Ten minutes is the default because it is short enough to run without planning
for it. It is not long enough to conclude anything from finding nothing.

## Examining what a campaign produced

A campaign runs without sanitizers and without coverage instrumentation,
because both cost throughput that would otherwise go into finding inputs.
Everything the campaign kept is examined afterwards, through builds that have
them.

    ./replay.sh <target>

replays every input the campaign kept through a build with the address and
undefined behaviour sanitizers, and fails if any of them does. This is where a
memory error is detected that the campaign itself would not have noticed, since
a crash is only reported to the fuzzer when the process actually dies.

    ./coverage.sh <target> [source directory ...]

replays the same inputs through a build instrumented for coverage, and reports
the proportion of each source file that was executed, under `os/net` by
default. The fuzzer reports whether it is still finding new execution paths,
which is not the same as which code it has reached. A parser that stays at
nothing is one that the seeds or the entry point are not reaching, and that is
a better thing to act on than a longer campaign.

Both replay one input to a process, which is why the harness processes one
input per process to begin with.

## Targets

A target is one campaign: one entry point of the stack, one seed corpus, one
dictionary, and the set of protocols linked into the harness.

    targets/rpl-icmpv6/
      target.conf     entry point, protocols to link, dictionary to use
      seeds/          starting inputs
      rpl.dict        tokens that the fuzzer inserts into mutations

Input is never injected at more than one entry point in the same run. The run
is what the fuzzer accounts coverage against, so mixing formats within it would
both confuse that accounting and spread mutation effort across unrelated
inputs.

The current targets are:

| Target | Entry point | Reaches |
| --- | --- | --- |
| `rpl-icmpv6` | ICMPv6 | the RPL control message parsers |
| `rpl-icmpv6-seq` | ICMPv6 | the same, after joining a DAG, from a sequence |
| `rpl-dao` | ICMPv6, as a root | destination advertisement parsing and route installation |
| `uip` | IPv6 | the IPv6 input path, including extension headers |
| `snmp` | SNMP | the SNMP engine and its BER decoder |
| `coap` | CoAP | the CoAP message parser |

## Sequences

An input is normally a single message, which is what a parser that holds no
state needs, and which lets a corpus be taken unchanged from a capture or from
another test.

A target that sets `FUZZ_SEQUENCE=1` takes a sequence instead: each message is
preceded by its length, in two bytes, most significant first, and the messages
are delivered in order to the same entry point. This is how a protocol whose
parser only becomes meaningful once a session exists is reached. The session is
established by the messages that precede the one under test, so the harness
never has to assemble the state of the protocol itself.

Framing is not applied to every target, because on a stateless parser it would
only spend mutations on length fields that carry no protocol meaning.

Almost every mutated input is malformed at the framing rather than at the
protocol, so a length that overruns the input is clamped and a truncated record
ends the sequence. At most sixteen messages are taken from one input, which
keeps a mutated input from becoming a long run that the fuzzer would report as
a hang.

## Adding a target

1. Create `targets/<name>/` with a `target.conf`, a `seeds` directory, and
   optionally a dictionary.
2. If the protocol needs an entry point that the harness does not have yet,
   add one to `fuzz-harness/fuzz-harness.c`.
3. If it needs a module, add it to `fuzz-harness/Makefile` behind a
   `FUZZ_PROTOCOLS` entry.

Nothing outside this directory needs to change.

## Adding an entry point

An entry point is a name, an optional setup function, and an injection
function:

    {"snmp", setup_snmp, inject_snmp_packet},

The setup function prepares whatever state the entry point needs. It runs once,
before the fork server starts, so it costs nothing per input, and every input is
processed against the same prepared state.

**Do not build a protocol's state structures by hand.** State that is assembled
in the harness stops matching the implementation as soon as the implementation
changes, and it can represent situations that the real code never reaches, which
produces findings that are not real. Prepare state through the protocol's own
interface, or not at all. Protocols fall into three groups:

- **No state.** The parser takes a buffer. The IPv6, ICMPv6 and adaptation
  layer entry points are here, as are SNMP and CoAP.
- **Local state, no peer.** The setup function uses the protocol's own
  interface. The `icmpv6-rpl-root` entry point is the example: it makes the
  node a root through `NETSTACK_ROUTING`, which is what reaches the parsing of
  destination advertisements. A node that is not a root cannot get there from
  injected packets at all, because the objective function has no link
  statistics to compute a rank from, so it joins with an infinite rank and
  rejects what follows. The DNS resolver belongs here too: `resolv_query()`
  leaves an entry in `STATE_ASKING`, and a response is only processed against
  such an entry. That the query itself goes nowhere does not matter.
- **A peer or a live session is required.** An MQTT client parsing broker
  replies, the TCP data path, and EDHOC. These do not get a setup function.
  Their state comes from the input instead, as a recorded session that the
  fuzzer mutates.

An injection function returns false only when the harness itself could not
proceed. A parser that rejects malformed input has behaved correctly, and must
not be reported as a failure.

## Seeds

Seeds decide what the campaign can reach, and are worth more attention than the
duration. A seed should be a valid message that exercises the parser, minimised
with `afl-tmin` before being committed. A corpus can be reduced with `afl-cmin`.

Useful sources are the corpora in `tests/20-packet-parsing`, and captures taken
from the Cooja simulations elsewhere under `tests/`, which are the natural way
to obtain the recorded sessions that a stateful protocol needs.

## Running on macOS

AFL++ refuses to start while crashes are forwarded to the system crash
reporter, because the delay before a crash is relayed to the fuzzer would make
it look like a timeout. Unload the reporter once per boot:

    SL=/System/Library; PL=com.apple.ReportCrash
    launchctl unload -w ${SL}/LaunchAgents/${PL}.plist
    sudo launchctl unload -w ${SL}/LaunchDaemons/${PL}.Root.plist

A System V shared memory segment is limited to `kern.sysv.shmmax`, four
megabytes by default, which is less than AFL++ asks for, so a campaign would
fail to start with `shmget() failed`. The script asks for a coverage map of the
customary size, which fits and is far more than these targets use, so no system
limit has to be changed. Set `AFL_MAP_SIZE` to override it.

Note also that the fork server is slower on macOS than on Linux, which matters
more for the ten minute default than for a long campaign.

## Background

This directory builds on the aSSIsT project, funded by the Swedish Foundation
for Strategic Research, which evaluated eight mutation-based and hybrid fuzzers
against the Contiki-NG network stack. The results are reported in:

> Clement Poncelet, Kostis Sagonas and Nicolas Tsiftes. So Many Fuzzers, So
> Little Time: Experience from Evaluating Fuzzers on the Contiki-NG Network
> (Hay)Stack. ASE 2022. <https://doi.org/10.1145/3551349.3556946>

The artifact, which contains the harness this one derives from, the fuzzer
configurations, and a ground truth of twenty Contiki-NG vulnerabilities mapped
to the pull requests that fixed them, is at
<https://github.com/assist-project/so-many-fuzzers-artifact>.

The project has ended, but several of the vulnerabilities in that ground truth
were found in code that this directory still fuzzes.

## Notes

Checksum verification is disabled in the harness, so that mutated input reaches
the parsers instead of being rejected by the checks in `uip6.c`. Logging is
disabled because it dominates the run time of a single injection.

The harness builds RPL Classic, whereas the packet injector in
`tests/20-packet-parsing` uses the native default of RPL Lite, so that the two
together cover both implementations.

Persistent mode is deliberately not used. The stack keeps global state that
would carry over between inputs, which would make a failure depend on the
inputs that preceded it and stop it reproducing on its own.
