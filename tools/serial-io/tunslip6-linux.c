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

/* Linux-specific tunslip6 platform support. */

#include "tunslip6.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

/*---------------------------------------------------------------------------*/
int
tun_alloc(char *dev, int tap)
{
  struct ifreq ifr;
  int fd, ret;

  if((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    perror("can not open /dev/net/tun");
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_TAP   - TAP device
   *
   *        IFF_NO_PI - Do not provide packet information
   */
  ifr.ifr_flags = (tap ? IFF_TAP : IFF_TUN) | IFF_NO_PI;
  if(*dev != 0) {
    strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
  }

  if((ret = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    close(fd);
    fprintf(stderr, "can not tunsetiff to %s (flags=%08x): %s\n", dev, ifr.ifr_flags,
            strerror(errno));
    return ret;
  }

  /* get resulting tunnel name */
  strcpy(dev, ifr.ifr_name);
  return fd;
}
/*---------------------------------------------------------------------------*/
void
ifconf(const char *tundev, const char *ipaddr)
{
  if(timestamp) {
    stamptime();
  }
  run_command("ifconfig %s inet `hostname` mtu %d up", tundev, devmtu);
  if(timestamp) {
    stamptime();
  }
  run_command("ifconfig %s add %s", tundev, ipaddr);

  /* radvd needs a link local address for routing. Generate one a la
     sixxs/aiccu: a full parse, stripping off the prefix length. */
  {
    char lladdr[40];
    char c, *ptr = (char *)ipaddr;
    uint16_t digit, ai, a[8], colon_seen, double_colon_pos, n_elided;
    for(ai = 0; ai < 8; ai++) {
      a[ai] = 0;
    }
    ai = 0;
    colon_seen = double_colon_pos = 0;
    while((c = *ptr++) != 0) {
      if(c == '/') {
        break;
      }
      if(c == ':') {
        if(colon_seen) {
          double_colon_pos = ai;
        }
        colon_seen = 1;
        if(++ai > 7) {
          break;
        }
      } else {
        colon_seen = 0;
        digit = c - '0';
        if(digit > 9) {
          digit = 10 + (c & 0xdf) - 'A';
        }
        a[ai] = (a[ai] << 4) + digit;
      }
    }
    /* Get # elided and shift what's after to the end */
    n_elided = 8 - ai;
    for(uint16_t i = 0; i < n_elided; i++) {
      if(8 - i - n_elided <= double_colon_pos) {
        a[7 - i] = 0;
      } else {
        a[7 - i] = a[8 - i - n_elided];
        a[8 - i - n_elided] = 0;
      }
    }
    sprintf(lladdr, "fe80::%x:%x:%x:%x", a[1] & 0xfefd, a[2], a[3], a[7]);
    if(timestamp) {
      stamptime();
    }
    run_command("ifconfig %s add %s/64", tundev, lladdr);
  }

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
  if(timestamp) {
    stamptime();
  }
  run_command("netstat -nr"
              " | awk '{ if ($2 == \"%s\") print \"route delete -net \"$1; }'"
              " | sh",
              tundev);
}
/*---------------------------------------------------------------------------*/
