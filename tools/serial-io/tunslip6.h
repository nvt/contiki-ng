/*
 * Copyright (c) 2001, Adam Dunkels.
 * Copyright (c) 2009, 2010 Joakim Eriksson, Niclas Finne, Dogan Yazar.
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
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
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the uIP TCP/IP stack.
 *
 *
 */

#ifndef TUNSLIP6_H_
#define TUNSLIP6_H_

#include <stdbool.h>

/*
 * Shared state and helpers defined in tunslip6.c and used by the
 * per-platform implementations in tunslip6-<os>.c.
 */
extern bool timestamp;
extern int devmtu;
extern char tundev[];
extern const char *ipaddr;

int run_command(const char *fmt, ...)
__attribute__((__format__(__printf__, 1, 2)));
void stamptime(void);
int devopen(const char *dev, int flags);

/*
 * Per-platform implementations, selected at build time in the Makefile and
 * defined in tunslip6-linux.c, tunslip6-macos.c, or tunslip6-bsd.c.
 */
int tunslip_open_tun(char *dev);

/*
 * Read one packet from / write one packet to the tun device, handling any
 * platform-specific framing (e.g. the 4-byte macOS utun protocol header).
 * tunslip_read_packet() returns the payload length; both abort on I/O error.
 */
int tunslip_read_packet(int fd, unsigned char *buf, int size);
void tunslip_write_packet(int fd, const unsigned char *buf, int len);

void tunslip_ifconf(const char *tundev, const char *ipaddr);

/*
 * Restore the host network configuration at exit. Best-effort: run_command()
 * reports any failure, but tunslip_cleanup() runs all of its commands and never
 * aborts, since some (e.g. removing a route that is already gone) can fail
 * harmlessly during shutdown.
 */
void tunslip_cleanup(void);

#endif /* TUNSLIP6_H_ */
