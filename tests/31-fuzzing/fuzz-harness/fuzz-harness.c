/*
 * Copyright (c) 2019, RISE Research Institutes of Sweden AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * \file
 *   Fuzzing harness for the Contiki-NG network stack input paths.
 *
 *   The harness reads a single packet from a file and injects it at a
 *   selected entry point. One input is processed per process, so that an
 *   input that causes a failure reproduces on its own when the fuzzer
 *   output is replayed later.
 *
 *   This harness derives from the packet injector in
 *   tests/20-packet-parsing, and from the fuzzing harness developed in the
 *   aSSIsT project.
 * \author
 *   Nicolas Tsiftes <nicolas.tsiftes@ri.se>
 */

#include "contiki.h"

/* Standard C and POSIX headers. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/* Contiki-NG headers. */
#include "net/ipv6/uip.h"
#include "net/ipv6/uip-icmp6.h"
#include "net/ipv6/sicslowpan.h"
#include "net/netstack.h"
#include "net/packetbuf.h"
#include "sys/cc.h"

/* Log configuration. */
#include "sys/log.h"
#define LOG_MODULE "Fuzzer"
#define LOG_LEVEL LOG_LEVEL_NONE

#define FUZZ_ENTRY_POINT_DEFAULT "uip"
#define FUZZ_BUFFER_SIZE 2000

extern int contiki_argc;
extern char **contiki_argv;

typedef bool (*entry_point_function_t)(const char *, int);

/*---------------------------------------------------------------------------*/
PROCESS(fuzz_harness_process, "Fuzzing harness process");
AUTOSTART_PROCESSES(&fuzz_harness_process);
/*---------------------------------------------------------------------------*/
static int
read_input(const char *filename, char *buf, int max_len)
{
  int fd;
  int len;

  fd = open(filename, O_RDONLY);
  if(fd < 0) {
    fprintf(stderr, "open %s: %s\n", filename, strerror(errno));
    return -1;
  }

  len = read(fd, buf, max_len);
  if(len < 0) {
    fprintf(stderr, "read %s: %s\n", filename, strerror(errno));
    close(fd);
    return -1;
  }

  close(fd);
  return len;
}
/*---------------------------------------------------------------------------*/
static void
set_uip_buf(const char *data, int len)
{
  if(len > sizeof(uip_buf)) {
    len = sizeof(uip_buf);
  }

  uip_len = len;
  memcpy(uip_buf, data, len);
}
/*---------------------------------------------------------------------------*/
/*
 * Inject at the IPv6 layer. The input is a complete IPv6 packet, and every
 * header is parsed before the payload is reached.
 */
static bool
inject_uip_packet(const char *data, int len)
{
  set_uip_buf(data, len);
  uip_input();

  return true;
}
/*---------------------------------------------------------------------------*/
/*
 * Inject at the ICMPv6 layer, which reaches the RPL control message parsers
 * without having to satisfy the IPv6 header checks first.
 */
static bool
inject_icmpv6_packet(const char *data, int len)
{
  set_uip_buf(data, len);
  uip_icmp6_input(UIP_ICMP_BUF->type, UIP_ICMP_BUF->icode);

  return true;
}
/*---------------------------------------------------------------------------*/
/*
 * Inject at the adaptation layer. The input is a 6LoWPAN frame that is
 * decompressed before the resulting IPv6 packet is parsed.
 */
static bool
inject_sicslowpan_packet(const char *data, int len)
{
  packetbuf_copyfrom(data, len);

  NETSTACK_NETWORK.input();
  NETSTACK_FRAMER.parse();

  sicslowpan_driver.input();

  return true;
}
/*---------------------------------------------------------------------------*/
static entry_point_function_t
select_entry_point(const char *name)
{
  struct entry_point_mapper {
    const char *name;
    entry_point_function_t function;
  };
  static const struct entry_point_mapper map[] = {
    {"icmpv6", inject_icmpv6_packet},
    {"sicslowpan", inject_sicslowpan_packet},
    {"uip", inject_uip_packet}
  };
  int i;

  if(name == NULL) {
    return NULL;
  }

  for(i = 0; i < CC_ARRAY_LENGTH(map); i++) {
    if(strcasecmp(name, map[i].name) == 0) {
      return map[i].function;
    }
  }

  return NULL;
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(fuzz_harness_process, ev, data)
{
  static char input_buf[FUZZ_BUFFER_SIZE];
  static int len;
  static const char *filename;
  static const char *entry_point_name;
  static entry_point_function_t entry_point;

  PROCESS_BEGIN();

  entry_point_name = getenv("FUZZ_ENTRY_POINT");
  if(entry_point_name == NULL) {
    entry_point_name = FUZZ_ENTRY_POINT_DEFAULT;
  }

  entry_point = select_entry_point(entry_point_name);
  if(entry_point == NULL) {
    fprintf(stderr, "unsupported entry point: \"%s\"\n", entry_point_name);
    exit(EXIT_FAILURE);
  }

  if(contiki_argc < 2) {
    fprintf(stderr, "usage: fuzz-harness <input file>\n");
    exit(EXIT_FAILURE);
  }
  filename = contiki_argv[1];

  /*
   * Start the fork server here, after the network stack has been
   * initialized but before the input is read. Every input is then processed
   * by a fresh copy of the same initialized state, which keeps a failing
   * input reproducible on its own. Persistent mode is deliberately not used,
   * because the stack keeps global state that would carry over between
   * inputs and make a failure depend on the ones that preceded it.
   */
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  len = read_input(filename, input_buf, FUZZ_BUFFER_SIZE);
  if(len < 0) {
    exit(EXIT_FAILURE);
  }

  if(entry_point(input_buf, len) == false) {
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
