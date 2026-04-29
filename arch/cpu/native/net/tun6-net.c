/*
 * Copyright (c) 2011, Swedish Institute of Computer Science.
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
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 */

#include "contiki.h"
#include "sys/platform.h"
#include "net/ipv6/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/netstack.h"
#include "net/ipv6/uiplib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <err.h>

#define TUN_PRIO CONTIKI_VERBOSE_PRIO + 30
/*---------------------------------------------------------------------------*/
/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "Tun6"
#define LOG_LEVEL LOG_LEVEL_WARN

#ifdef __APPLE__
/* utun0-3 are in use on Big Sur, so use utun10 as default */
#define DEFAULT_TUN "utun10"
#else /* __APPLE__ */
#define DEFAULT_TUN "tun0"
#endif /* __APPLE__ */

#define DEFAULT_PREFIX "fd00::1/64"
static const char *config_ipaddr = DEFAULT_PREFIX;
static char config_tundev[IFNAMSIZ + 1] = DEFAULT_TUN;
static void (* tun_input_callback)(void);

/* IPv6 required minimum MTU */
#define MIN_MTU_SIZE 1500
static int config_mtu = MIN_MTU_SIZE;

static int tunfd = -1;

static int set_fd(fd_set *rset, fd_set *wset);
static void handle_fd(fd_set *rset, fd_set *wset);
static const struct select_callback tun_select_callback = {
  set_fd,
  handle_fd
};

/*
 * Execute argv via fork()+execvp(), waiting for the child to exit. The
 * parent never passes attacker-influenced strings through /bin/sh, so
 * shell metacharacters in --prefix or -t cannot inject commands.
 */
static int
run_command(const char *const argv[])
{
  if(LOG_LEVEL >= LOG_LEVEL_INFO) {
    LOG_INFO("exec:");
    for(const char *const *a = argv; *a != NULL; a++) {
      LOG_INFO_(" %s", *a);
    }
    LOG_INFO_("\n");
    fflush(stdout);
  }

  pid_t pid = fork();
  if(pid < 0) {
    perror("fork");
    return -1;
  }
  if(pid == 0) {
    execvp(argv[0], (char *const *)argv);
    perror("execvp");
    _exit(127);
  }

  int status;
  while(waitpid(pid, &status, 0) < 0) {
    if(errno == EINTR) {
      continue;
    }
    perror("waitpid");
    return -1;
  }
  if(WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  return -1;
}

/* Self-pipe written from sigcleanup() so the main loop can run the
 * (non async-signal-safe) cleanup path from libc context. */
static int shutdown_pipe[2] = { -1, -1 };

static int
shutdown_set_fd(fd_set *rset, fd_set *wset)
{
  if(shutdown_pipe[0] < 0) {
    return 0;
  }
  FD_SET(shutdown_pipe[0], rset);
  return 1;
}

static void
shutdown_handle_fd(fd_set *rset, fd_set *wset)
{
  /*
   * The platform main loop dispatches handle_fd to every registered
   * callback whenever select() returns >0, leaving each callback to
   * gate on FD_ISSET itself. Without this check, any unrelated fd
   * becoming readable (TUN packet, stdin EOF) would terminate the
   * process before a signal had been delivered.
   */
  if(shutdown_pipe[0] < 0 || !FD_ISSET(shutdown_pipe[0], rset)) {
    return;
  }
  /* atexit-registered cleanup() will run from inside exit(). */
  exit(EXIT_SUCCESS);
}

static const struct select_callback shutdown_select_callback = {
  shutdown_set_fd,
  shutdown_handle_fd
};

/*---------------------------------------------------------------------------*/
static bool
set_default_prefix(const char *prefix)
{
  char *ipaddr = strdup(prefix);
  if(!ipaddr) {
    return false;
  }

  bool success = false;
  char *s = strchr(ipaddr, '/');
  if(s) {
    uip_ip6addr_t prefix_addr;
    *s = '\0';
    if(uiplib_ipaddrconv(ipaddr, &prefix_addr)) {
      uip_ds6_set_default_prefix(&prefix_addr);
      success = true;
    }
  }
  free(ipaddr);
  return success;
}
/*---------------------------------------------------------------------------*/
const char *
tun6_net_get_prefix(void)
{
  return config_ipaddr;
}
/*---------------------------------------------------------------------------*/
void
tun6_net_set_prefix(const char *prefix)
{
  if(!set_default_prefix(prefix)) {
    LOG_WARN("Failed to set default prefix %s\n", prefix);
  }
  config_ipaddr = prefix;
}
/*---------------------------------------------------------------------------*/
const char *
tun6_net_get_tun_name(void)
{
  return config_tundev;
}
/*---------------------------------------------------------------------------*/
void
tun6_net_set_tun_name(const char *tun_name)
{
  /* Ignore "/dev/" if present in tun device name */
  if(strncmp("/dev/", tun_name, 5) == 0) {
    tun_name += 5;
  }
  strncpy(config_tundev, tun_name, sizeof(config_tundev) - 1);
  config_tundev[sizeof(config_tundev) - 1] = '\0';
}
/*---------------------------------------------------------------------------*/
int
tun6_net_get_mtu(void)
{
  return config_mtu;
}
/*---------------------------------------------------------------------------*/
void
tun6_net_set_mtu(int mtu_size)
{
  if(mtu_size < MIN_MTU_SIZE) {
    LOG_WARN("ignoring too small MTU size %d, using %d\n",
             mtu_size, config_mtu);
  } else {
    config_mtu = mtu_size;
  }
}
/*---------------------------------------------------------------------------*/
static int
tun_dev_callback(const char *optarg)
{
  tun6_net_set_tun_name(optarg);
  return 0;
}
CONTIKI_OPTION(TUN_PRIO, { "t", required_argument, NULL, 0 },
               tun_dev_callback,
               "name of tun interface (default: " DEFAULT_TUN ")\n");

/*---------------------------------------------------------------------------*/
static int
prefix_callback(const char *optarg)
{
  tun6_net_set_prefix(optarg);
  return 0;
}
CONTIKI_OPTION(TUN_PRIO + 1, { "prefix", required_argument, NULL, 0 },
               prefix_callback,
               "Subnet prefix (default: " DEFAULT_PREFIX ")\n");
/*---------------------------------------------------------------------------*/
static int
mtu_callback(const char *optarg)
{
  tun6_net_set_mtu(atoi(optarg));
  return 0;
}
CONTIKI_OPTION(TUN_PRIO + 2, { "mtu", required_argument, NULL, 0 },
               mtu_callback, "interface MTU size\n");
/*---------------------------------------------------------------------------*/
static void
cleanup(void)
{
#ifdef __APPLE__
  {
    const char *const argv[] = {
      "ifconfig", config_tundev, "inet6", config_ipaddr, "remove", NULL
    };
    run_command(argv);
  }
#endif /* __APPLE__ */

  {
    const char *const argv[] = {
      "ifconfig", config_tundev, "down", NULL
    };
    run_command(argv);
  }

  /*
   * Previously this also ran a "netstat -nr | awk ... | sh" pipeline to
   * delete leftover routes (and a sysctl on non-Linux non-Apple). The
   * pipeline relied on /bin/sh, was Linux-broken because Linux
   * netstat(1) has different column layout, and post privilege drop
   * would not have permission to flush routes anyway. The TUN device is
   * destroyed when the fd is closed on Linux, so route entries
   * referencing it become unreachable on their own.
   */
}
/*---------------------------------------------------------------------------*/
/*
 * Async-signal-safe handler: only writes a byte to a pipe registered
 * with select(). The main loop wakes up, calls shutdown_handle_fd(),
 * which calls exit() and runs the atexit-registered cleanup() from
 * normal libc context.
 */
static void
sigcleanup(int signo)
{
  const char *prefix = "signal ";
  const char *sig =
    signo == SIGHUP ? "HUP\n" : signo == SIGTERM ? "TERM\n" : "INT\n";
  ssize_t r;
  r = write(STDERR_FILENO, prefix, strlen(prefix));
  r = write(STDERR_FILENO, sig, strlen(sig));
  if(shutdown_pipe[1] >= 0) {
    unsigned char b = 1;
    r = write(shutdown_pipe[1], &b, 1);
  }
  (void)r;
}
/*---------------------------------------------------------------------------*/
static void
ifconf_setup(void)
{
  char mtu_str[16];
  snprintf(mtu_str, sizeof(mtu_str), "%d", config_mtu);

#if defined(linux) || (!defined(__APPLE__))
  char hostname[HOST_NAME_MAX + 1];
  if(gethostname(hostname, sizeof(hostname)) != 0) {
    perror("gethostname");
    hostname[0] = '\0';
  }
  hostname[sizeof(hostname) - 1] = '\0';
#endif

#ifdef linux
  {
    const char *const argv[] = {
      "ifconfig", config_tundev, "inet", hostname,
      "mtu", mtu_str, "up", NULL
    };
    run_command(argv);
  }
  {
    const char *const argv[] = {
      "ifconfig", config_tundev, "add", config_ipaddr, NULL
    };
    run_command(argv);
  }
#elif defined(__APPLE__)
  {
    const char *const argv[] = {
      "ifconfig", config_tundev, "inet6", "mtu", mtu_str, "up", NULL
    };
    run_command(argv);
  }
  {
    const char *const argv[] = {
      "ifconfig", config_tundev, "inet6", config_ipaddr, "add", NULL
    };
    run_command(argv);
  }
  {
    const char *const argv[] = {
      "sysctl", "-w", "net.inet6.ip6.forwarding=1", NULL
    };
    run_command(argv);
  }
#else
  {
    const char *const argv[] = {
      "ifconfig", config_tundev, "inet", hostname, config_ipaddr,
      "mtu", mtu_str, "up", NULL
    };
    run_command(argv);
  }
  {
    const char *const argv[] = {
      "sysctl", "-w", "net.inet.ip.forwarding=1", NULL
    };
    run_command(argv);
  }
#endif /* !linux */

  /* Print the configuration to the console. */
  {
    const char *const argv[] = { "ifconfig", config_tundev, NULL };
    run_command(argv);
  }
}
/*---------------------------------------------------------------------------*/
#ifdef linux
#include <linux/if.h>
#include <linux/if_tun.h>

static int
tun_alloc(void)
{
  struct ifreq ifr;
  int fd, err;

  LOG_INFO("Opening tun interface %s\n", config_tundev);

  if((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    /* Error message handled by caller */
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_NO_PI - Do not provide packet information
   */
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if(*config_tundev != '\0') {
    strncpy(ifr.ifr_name, config_tundev, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
  }

  if((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    /* Error message handled by caller */
    close(fd);
    return err;
  }

  LOG_INFO("Using '%s' as '%s'\n", config_tundev, ifr.ifr_name);
  strncpy(config_tundev, ifr.ifr_name, sizeof(config_tundev) - 1);
  config_tundev[sizeof(config_tundev) - 1] = '\0';
  return fd;
}
#elif defined __APPLE__
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <sys/uio.h>

/*
 * Reference for utun on macOS:
 * http://newosxbook.com/src.jl?tree=listings&file=17-15-utun.c
 */
static int
tun_alloc(void)
{
  unsigned int tunif;

  if(sscanf(config_tundev, "utun%u", &tunif) != 1 || tunif >= UINT8_MAX) {
    fprintf(stderr, "tun_alloc: invalid utun interface specified: %s\n", config_tundev);
    return -1;
  }

  LOG_INFO("Opening tun interface %s\n", config_tundev);

  struct ctl_info ctl_info = { 0 };
  if(strlcpy(ctl_info.ctl_name, UTUN_CONTROL_NAME, sizeof(ctl_info.ctl_name)) >=
      sizeof(ctl_info.ctl_name)) {
    fprintf(stderr, "UTUN_CONTROL_NAME too long");
    return -1;
  }

  int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
  if(fd == -1) {
    perror("socket(SYSPROTO_CONTROL)");
    return -1;
  }

  if(ioctl(fd, CTLIOCGINFO, &ctl_info) == -1) {
    perror("ioctl(CTLIOCGINFO)");
    close(fd);
    return -1;
  }

  struct sockaddr_ctl sc;
  sc.sc_id = ctl_info.ctl_id;
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
#else
static int
tun_alloc(void)
{
  char t[8 + sizeof(config_tundev)] = "/dev/";
  strncat(t, config_tundev, sizeof(t) - 6);
  t[sizeof(t) - 1] = '\0';
  LOG_INFO("Opening tun interface %s\n", t);
  return open(t, O_RDWR);
}
#endif
/*---------------------------------------------------------------------------*/
/*
 * Drop root privileges after the TUN fd is open and the interface has
 * been configured. The TUN fd survives setuid(), so subsequent reads,
 * writes, and selects on it work as the unprivileged user. The atexit
 * cleanup that runs ifconfig/route may fail post-drop; on Linux the TUN
 * device disappears once the fd is closed, so explicit teardown there
 * is best-effort.
 */
static void
drop_privileges(void)
{
  if(geteuid() != 0) {
    return;
  }

  const char *sudo_uid_str = getenv("SUDO_UID");
  const char *sudo_gid_str = getenv("SUDO_GID");
  if(sudo_uid_str == NULL || sudo_gid_str == NULL) {
    LOG_WARN("Running as root without sudo; not dropping privileges. "
             "Re-run via 'sudo' so the app stack runs unprivileged.\n");
    return;
  }

  char *end;
  long uid = strtol(sudo_uid_str, &end, 10);
  if(*sudo_uid_str == '\0' || *end != '\0' || uid <= 0) {
    LOG_ERR("Invalid SUDO_UID; refusing to start.\n");
    exit(EXIT_FAILURE);
  }
  long gid = strtol(sudo_gid_str, &end, 10);
  if(*sudo_gid_str == '\0' || *end != '\0' || gid <= 0) {
    LOG_ERR("Invalid SUDO_GID; refusing to start.\n");
    exit(EXIT_FAILURE);
  }
  uid_t target_uid = (uid_t)uid;
  gid_t target_gid = (gid_t)gid;

  struct passwd *pw = getpwuid(target_uid);
  if(pw != NULL) {
    if(initgroups(pw->pw_name, target_gid) != 0) {
      perror("initgroups");
      exit(EXIT_FAILURE);
    }
  } else if(setgroups(0, NULL) != 0) {
    perror("setgroups");
    exit(EXIT_FAILURE);
  }
  if(setgid(target_gid) != 0) {
    perror("setgid");
    exit(EXIT_FAILURE);
  }
  if(setuid(target_uid) != 0) {
    perror("setuid");
    exit(EXIT_FAILURE);
  }
  if(setuid(0) == 0) {
    LOG_ERR("Privilege drop failed: still able to setuid(0)\n");
    exit(EXIT_FAILURE);
  }
  LOG_INFO("Dropped privileges to uid=%ld gid=%ld\n",
           (long)target_uid, (long)target_gid);
}
/*---------------------------------------------------------------------------*/
bool
tun6_net_init(void (* tun_input)(void))
{
  if(!tun_input) {
    return false;
  }
  tun_input_callback = tun_input;

  setvbuf(stdout, NULL, _IOLBF, 0); /* Line buffered output. */

  tunfd = tun_alloc();
  if(tunfd == -1) {
    return false;
  }

  LOG_INFO("Tun open:%d\n", tunfd);

  select_set_callback(tunfd, &tun_select_callback);

  fprintf(stderr, "opened %s device ``/dev/%s''\n",
          "tun", config_tundev);

  if(pipe(shutdown_pipe) != 0) {
    perror("pipe");
    return false;
  }
  for(int i = 0; i < 2; i++) {
    int fl = fcntl(shutdown_pipe[i], F_GETFL, 0);
    if(fl >= 0) {
      fcntl(shutdown_pipe[i], F_SETFL, fl | O_NONBLOCK);
    }
    int fd_fl = fcntl(shutdown_pipe[i], F_GETFD, 0);
    if(fd_fl >= 0) {
      fcntl(shutdown_pipe[i], F_SETFD, fd_fl | FD_CLOEXEC);
    }
  }
  select_set_callback(shutdown_pipe[0], &shutdown_select_callback);

  atexit(cleanup);
  signal(SIGHUP, sigcleanup);
  signal(SIGTERM, sigcleanup);
  signal(SIGINT, sigcleanup);
  ifconf_setup();
  drop_privileges();
  return true;
}
/*---------------------------------------------------------------------------*/
int
tun6_net_output(uint8_t *data, int len)
{
  if(tunfd == -1) {
    return 0;
  }

#ifdef __APPLE__
  /* Fake IFF_NO_PI on macOS by sending a 4 byte header containing AF_INET6 */
  u_int32_t type = htonl(AF_INET6);
  struct iovec iv[2];

  iv[0].iov_base = &type;
  iv[0].iov_len = sizeof(type);
  iv[1].iov_base = data;
  iv[1].iov_len = len;

  if(writev(tunfd, iv, 2) != (sizeof(type) + len)) {
    err(EXIT_FAILURE, "tun6_net_output: writev");
  }
#else
  if(write(tunfd, data, len) != len) {
    err(EXIT_FAILURE, "tun6_net_output: write");
  }
#endif

  return 0;
}
/*---------------------------------------------------------------------------*/
int
tun6_net_input(uint8_t *data, int maxlen)
{
  int size;

  if(tunfd == -1) {
    /* tun is not open */
    return 0;
  }

  if((size = read(tunfd, data, maxlen)) == -1) {
    err(EXIT_FAILURE, "tun6_net_input: read");
  }

#ifdef __APPLE__
#define UTUN_HEADER_LEN 4
  /* Fake IFF_NO_PI on macOS by ignoring the first 4 bytes containing AF_INET6 */
  if(size <= UTUN_HEADER_LEN) {
    err(EXIT_FAILURE, "tun6_net_input: read too small");
  }

  size -= UTUN_HEADER_LEN;
  memmove(data, data + UTUN_HEADER_LEN, size);
#undef UTUN_HEADER_LEN
#endif /* __APPLE__ */

  return size;
}

/*---------------------------------------------------------------------------*/
/* tun select callback                                                       */
/*---------------------------------------------------------------------------*/
static int
set_fd(fd_set *rset, fd_set *wset)
{
  if(tunfd == -1) {
    return 0;
  }

  FD_SET(tunfd, rset);
  return 1;
}
/*---------------------------------------------------------------------------*/
static void
handle_fd(fd_set *rset, fd_set *wset)
{
  if(tunfd == -1) {
    /* tun is not open */
    return;
  }

  if(FD_ISSET(tunfd, rset)) {
    tun_input_callback();
  }
}

/*---------------------------------------------------------------------------*/
/* network callbacks                                                         */
/*---------------------------------------------------------------------------*/
static void
tun_input(void)
{
  int size = tun6_net_input(uip_buf, sizeof(uip_buf));
  LOG_DBG("TUN data incoming read:%d\n", size);
  uip_len = size;
  tcpip_input();
}
/*---------------------------------------------------------------------------*/
static void
network_init(void)
{
  if(!tun6_net_init(tun_input)) {
    LOG_WARN("Failed to open tun device (you may be lacking permission). Running without network.\n");
  }
}
/*---------------------------------------------------------------------------*/
static uint8_t
network_output(const linkaddr_t *localdest)
{
  if(uip_len > 0) {
    LOG_DBG("output: %u bytes to ", uip_len);
    LOG_DBG_LLADDR(localdest);
    LOG_DBG_("\n");
    return tun6_net_output(uip_buf, uip_len);
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
static void
network_input(void)
{
  /* should not happen */
  LOG_DBG("unexpected network input\n");
}
/*---------------------------------------------------------------------------*/
const struct network_driver tun6_net_driver = {
  "tun6",
  network_init,
  network_input,
  network_output
};
/*---------------------------------------------------------------------------*/
