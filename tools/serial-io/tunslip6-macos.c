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

/* macOS-specific tunslip6 platform support (utun). */

#include "tunslip6.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <err.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>

/*
 * Reference for utun on macOS:
 * http://newosxbook.com/src.jl?tree=listings&file=17-15-utun.c
 */
/*---------------------------------------------------------------------------*/
int
tun_alloc(char *dev, int tap)
{
  struct sockaddr_ctl sc;
  struct ctl_info ctlInfo;
  int fd;
  unsigned int tunif;

  if(tap) {
    errx(EXIT_FAILURE, "tun_alloc: TAP is not supported with utun on macOS");
    return -1;
  }

  if(sscanf(dev, "utun%u", &tunif) != 1 || tunif >= UINT8_MAX) {
    errx(EXIT_FAILURE, "tun_alloc: invalid utun interface specified");
    return -1;
  }

  memset(&ctlInfo, 0, sizeof(ctlInfo));
  if(strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name)) >=
     sizeof(ctlInfo.ctl_name)) {
    fprintf(stderr, "UTUN_CONTROL_NAME too long");
    return -1;
  }

  fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

  if(fd == -1) {
    perror("socket(SYSPROTO_CONTROL)");
    return -1;
  }

  if(ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1) {
    perror("ioctl(CTLIOCGINFO)");
    close(fd);
    return -1;
  }

  sc.sc_id = ctlInfo.ctl_id;
  sc.sc_len = sizeof(sc);
  sc.sc_family = AF_SYSTEM;
  sc.ss_sysaddr = AF_SYS_CONTROL;
  sc.sc_unit = tunif + 1;

  /*
   * If the connect is successful, a utun%d device will be created, where "%d"
   * is our unit number -1
   */

  if(connect(fd, (struct sockaddr *)&sc, sizeof(sc)) == -1) {
    perror("connect(AF_SYS_CONTROL)");
    close(fd);
    return -1;
  }

  return fd;
}
/*---------------------------------------------------------------------------*/
void
ifconf(const char *tundev, const char *ipaddr)
{
  if(timestamp) {
    stamptime();
  }
  run_command("ifconfig %s inet6 mtu %d up", tundev, devmtu);
  if(timestamp) {
    stamptime();
  }
  run_command("ifconfig %s inet6 %s add", tundev, ipaddr);
  if(timestamp) {
    stamptime();
  }
  run_command("sysctl -w net.inet6.ip6.forwarding=1");

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
  run_command("ifconfig %s inet6 %s remove", tundev, ipaddr);
  if(timestamp) {
    stamptime();
  }
  run_command("ifconfig %s down", tundev);
}
/*---------------------------------------------------------------------------*/
