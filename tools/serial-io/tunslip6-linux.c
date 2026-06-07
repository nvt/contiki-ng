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
 */

/* Linux-specific tunslip6 platform support. */

#include "tunslip6.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>   /* before <linux/if.h>: avoids struct in6_addr clash */
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>

/*---------------------------------------------------------------------------*/
int
tunslip_open_tun(char *dev, size_t devsize)
{
  struct ifreq ifr;
  int fd, ret;

  if((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    perror("can not open /dev/net/tun");
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_NO_PI - Do not provide packet information
   */
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if(*dev != 0) {
    strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
  }

  if((ret = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    close(fd);
    tunslip_log("can not tunsetiff to %s (flags=%08x): %s", dev, ifr.ifr_flags,
                strerror(errno));
    return ret;
  }

  /* get resulting tunnel name (kernel NUL-terminates ifr_name) */
  snprintf(dev, devsize, "%s", ifr.ifr_name);
  return fd;
}
/*---------------------------------------------------------------------------*/
size_t
tunslip_read_packet(int fd, unsigned char *buf, size_t size)
{
  ssize_t n = read(fd, buf, size);
  if(n == -1) {
    err(EXIT_FAILURE, "tunslip_read_packet");
  }
  return n;
}
/*---------------------------------------------------------------------------*/
void
tunslip_write_packet(int fd, const unsigned char *buf, size_t len)
{
  if(write(fd, buf, len) != (ssize_t)len) {
    err(EXIT_FAILURE, "tunslip_write_packet");
  }
}
/*---------------------------------------------------------------------------*/
void
tunslip_ifconf(const char *tundev, const char *ipaddr)
{
  run_command("ifconfig %s inet `hostname` mtu %d up", tundev, devmtu);
  run_command("ifconfig %s add %s", tundev, ipaddr);

  /*
   * radvd needs a link-local address for routing. Derive one (a la
   * sixxs/aiccu) from the configured global address: parse it with
   * inet_pton() and build fe80:: from selected 16-bit groups.
   */
  char addr_str[INET6_ADDRSTRLEN];
  size_t addr_len = strcspn(ipaddr, "/");   /* copy the address, dropping any /prefix */
  if(addr_len >= sizeof(addr_str)) {
    addr_len = sizeof(addr_str) - 1;
  }
  memcpy(addr_str, ipaddr, addr_len);
  addr_str[addr_len] = '\0';

  struct in6_addr global_addr;
  if(inet_pton(AF_INET6, addr_str, &global_addr) != 1) {
    tunslip_log("can't derive a link-local address from '%s'", ipaddr);
  } else {
    uint16_t group[8];
    for(int i = 0; i < 8; i++) {
      group[i] = (global_addr.s6_addr[2 * i] << 8) | global_addr.s6_addr[2 * i + 1];
    }
    char lladdr[INET6_ADDRSTRLEN];
    snprintf(lladdr, sizeof(lladdr), "fe80::%x:%x:%x:%x",
             group[1] & 0xfefd, group[2], group[3], group[7]);
    run_command("ifconfig %s add %s/64", tundev, lladdr);
  }

  run_command("ifconfig %s", tundev);
}
/*---------------------------------------------------------------------------*/
void
tunslip_cleanup(void)
{
  tunslip_log("cleaning up: restoring network configuration");
  run_command("ifconfig %s down", tundev);
  run_command("netstat -nr"
              " | awk '{ if ($2 == \"%s\") print \"route delete -net \"$1; }'"
              " | sh",
              tundev);
}
/*---------------------------------------------------------------------------*/
