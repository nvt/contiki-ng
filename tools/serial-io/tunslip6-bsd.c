/*
 * Copyright (c) 2001, Adam Dunkels.
 * Copyright (c) 2009, 2010 Joakim Eriksson, Niclas Finne, Dogan Yazar.
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

/* Generic BSD/other-Unix tunslip6 platform support. */

#include "tunslip6.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <fcntl.h>

/*---------------------------------------------------------------------------*/
int
tun_alloc(char *dev, int tap)
{
  (void)tap;
  return devopen(dev, O_RDWR);
}
/*---------------------------------------------------------------------------*/
int
tun_read(int fd, unsigned char *buf, int size)
{
  int n = read(fd, buf, size);
  if(n == -1) {
    err(EXIT_FAILURE, "tun_read");
  }
  return n;
}
/*---------------------------------------------------------------------------*/
void
tun_write(int fd, const unsigned char *buf, int len)
{
  if(write(fd, buf, len) != len) {
    err(EXIT_FAILURE, "tun_write");
  }
}
/*---------------------------------------------------------------------------*/
void
ifconf(const char *tundev, const char *ipaddr)
{
  if(timestamp) {
    stamptime();
  }
  run_command("ifconfig %s inet `hostname` %s mtu %d up", tundev, ipaddr, devmtu);
  if(timestamp) {
    stamptime();
  }
  run_command("sysctl -w net.inet.ip.forwarding=1");

  if(timestamp) {
    stamptime();
  }
  run_command("ifconfig %s\n", tundev);
}
/*---------------------------------------------------------------------------*/
void
cleanup(void)
{
  fprintf(stderr, "*** cleaning up: restoring network configuration\n");
  if(timestamp) {
    stamptime();
  }
  run_command("ifconfig %s down", tundev);
  run_command("sysctl -w net.ipv6.conf.all.forwarding=1");
  if(timestamp) {
    stamptime();
  }
  run_command("netstat -nr"
              " | awk '{ if ($2 == \"%s\") print \"route delete -net \"$1; }'"
              " | sh",
              tundev);
}
/*---------------------------------------------------------------------------*/
