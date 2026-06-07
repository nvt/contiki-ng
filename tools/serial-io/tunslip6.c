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

/* Below define allows importing saved output into Wireshark as "Raw IP" packet type */
#define WIRESHARK_IMPORT_FORMAT 1

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <err.h>

#include "tools-utils.h"
#include "tunslip6.h"

#ifndef BAUDRATE
#define BAUDRATE B115200
#endif
static speed_t baud_speed = BAUDRATE;

static int verbose = 2;
const char *ipaddr;
static int slipfd;
static uint16_t basedelay, delaymsec;
static time_t delaystartsec;
static long delaystartmsec;
bool timestamp = false;
static bool flowcontrol, showprogress, flowcontrol_xonxoff;
static bool quiet;   /* -q: suppress tunslip6's own messages */

/* Traffic counters, dumped on SIGUSR1 and at exit. */
static struct {
  unsigned long long rx_packets, rx_bytes;   /* SLIP -> tun */
  unsigned long long tx_packets, tx_bytes;   /* tun -> SLIP */
  unsigned long long dropped_oversize;       /* packets too big for the input buffer */
  unsigned long long queue_full;             /* serial output queue was full */
} stats;
static volatile sig_atomic_t want_stats;     /* set by SIGUSR1, served by the main loop */

/* ANSI styling for tunslip6's own log lines; resolved from color_mode at startup. */
static const char *log_style = "";
static const char *log_style_reset = "";

/* Color mode for tunslip6's own messages, selectable with -C. */
enum colormode { COLOR_AUTO, COLOR_ALWAYS, COLOR_NEVER };
static enum colormode color_mode = COLOR_AUTO;

static void write_to_serial(const void *inbuf, size_t len);

static void slip_send(unsigned char c);
static void slip_send_char(unsigned char c);

/*
 * Interface name buffer. Interface names are short (IFNAMSIZ is 16 on Linux);
 * 32 leaves headroom for platform variants such as macOS "utunN".
 */
#define TUNDEV_SIZE 32
char tundev[TUNDEV_SIZE] = { "" };

/* IPv6 required minimum MTU */
#define MIN_DEVMTU 1500
int devmtu = MIN_DEVMTU;

/* Maximum size of an IP packet carried over the tunnel, in either direction. */
#define TUN_BUFSIZE 2000
/*---------------------------------------------------------------------------*/
static void
progress(const char *s)
{
  if(showprogress) {
    fprintf(stderr, "%s", s);
  }
}
/*---------------------------------------------------------------------------*/
/* Shell commands embed an interface name and IPv6 addresses; size generously. */
#define SHELL_CMD_SIZE 256
/* Run a printf-formatted shell command, reporting any failure on stderr. */
int
run_command(const char *fmt, ...)
{
  char cmd[SHELL_CMD_SIZE];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(cmd, sizeof(cmd), fmt, ap);
  va_end(ap);
  tunslip_log("running: %s", cmd);

  /* Capture the command's stdout and stderr and re-emit each line through the
     same channel, so its output is tagged as tunslip6's rather than appearing
     plain on stdout like the mote's output. */
  char piped[SHELL_CMD_SIZE + sizeof(" 2>&1")];
  snprintf(piped, sizeof(piped), "%s 2>&1", cmd);

  FILE *fp = popen(piped, "r");
  if(fp == NULL) {
    tunslip_log("failed to run '%s': %s", cmd, strerror(errno));
    return -1;
  }

  char line[512];
  while(fgets(line, sizeof(line), fp) != NULL) {
    line[strcspn(line, "\n")] = '\0';
    if(line[0] != '\0') {   /* skip blank lines from the command's output */
      tunslip_log("  %s", line);
    }
  }

  int ret = pclose(fp);
  if(ret == -1) {
    tunslip_log("failed to run '%s': %s", cmd, strerror(errno));
  } else if(WIFSIGNALED(ret)) {
    tunslip_log("'%s' terminated by signal %d", cmd, WTERMSIG(ret));
  } else if(WIFEXITED(ret) && WEXITSTATUS(ret) != 0) {
    tunslip_log("'%s' exited with status %d", cmd, WEXITSTATUS(ret));
  }
  return ret;
}
/*---------------------------------------------------------------------------*/
#define SLIP_END      0300
#define SLIP_ESC      0333
#define SLIP_ESC_END  0334
#define SLIP_ESC_ESC  0335

#define SLIP_ESC_XON  0336
#define SLIP_ESC_XOFF 0337
#define XON           17
#define XOFF          19

#define DEBUG_LINE_MARKER '\r'
/*---------------------------------------------------------------------------*/
/* Return a pointer to the IPv4 or IPv6 address inside a sockaddr. */
static const void *
get_in_addr(const struct sockaddr *sa)
{
  if(sa->sa_family == AF_INET) {
    return &((const struct sockaddr_in *)sa)->sin_addr;
  }
  return &((const struct sockaddr_in6 *)sa)->sin6_addr;
}
/*---------------------------------------------------------------------------*/
/* Write the -L timestamp (if enabled) to out, ahead of the line it prefixes. */
static void
stamptime(FILE *out)
{
  static long startsecs, startmsecs;
  struct timeval tv;

  /* Timestamping is opt-in (-L); callers no longer need to guard on it. */
  if(!timestamp) {
    return;
  }

  if(gettimeofday(&tv, NULL) == -1) {
    /* Non-fatal: stamptime() is reached from the atexit tunslip_cleanup path
       (via tunslip_log), where calling exit() would be undefined. Skip it. */
    perror("gettimeofday");
    return;
  }
  long msecs = tv.tv_usec / 1000;
  long secs = tv.tv_sec;
  if(startsecs) {
    secs -= startsecs;
    msecs -= startmsecs;
    if(msecs < 0) {
      secs--;
      msecs += 1000;
    }
    fprintf(out, "%04lu.%03lu ", secs, msecs);
  } else {
    startsecs = secs;
    startmsecs = msecs;
    time_t t = time(NULL);
    struct tm *tmp = localtime(&t);
    char timec[sizeof("HH:MM:SS")];
    if(tmp != NULL && strftime(timec, sizeof(timec), "%T", tmp) > 0) {
      fprintf(out, "\n%s ", timec);
    } else {
      fprintf(out, "\n");
    }
  }
}
/*---------------------------------------------------------------------------*/
/* Print one of tunslip6's own messages on stderr (see tunslip6.h). */
void
tunslip_log(const char *fmt, ...)
{
  va_list ap;

  if(quiet) {
    return;
  }
  stamptime(stderr);
  fprintf(stderr, "%stunslip6: ", log_style);
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fprintf(stderr, "%s\n", log_style_reset);
}
/*---------------------------------------------------------------------------*/
static bool
is_sensible_string(const unsigned char *s, size_t len)
{
  for(size_t i = 1; i < len; i++) {
    if(s[i] == 0 || s[i] == '\r' || s[i] == '\n' || s[i] == '\t') {
      continue;
    } else if(s[i] < ' ' || '~' < s[i]) {
      return false;
    }
  }

  /* Edge-case: printable characters in flow label */
  if(len >= 2 && (s[0] & 0xF0) == 0x60
     && (s[1] == '\r' || s[1] == '\n' || s[1] == '\t')) {
    return false;
  }

  return true;
}
/*---------------------------------------------------------------------------*/
static void
print_packet_hex(const unsigned char *buf, size_t len)
{
#if WIRESHARK_IMPORT_FORMAT
  printf("0000");
  for(size_t i = 0; i < len; i++) {
    printf(" %02x", buf[i]);
  }
#else
  printf("         ");
  for(size_t i = 0; i < len; i++) {
    printf("%02x", buf[i]);
    if((i & 3) == 3) {
      printf(" ");
    }
    if((i & 15) == 15) {
      printf("\n         ");
    }
  }
#endif
  printf("\n");
}
/*---------------------------------------------------------------------------*/
/* Handle a "?P" command: reply with the configured IPv6 prefix. */
static void
handle_prefix_request(const unsigned char *inbuf, size_t len)
{
  if(len < 2 || inbuf[1] != 'P') {
    return;
  }

  char *s = strchr(ipaddr, '/');
  if(s != NULL) {
    *s = '\0';
  }
  struct in6_addr addr;
  if(inet_pton(AF_INET6, ipaddr, &addr) != 1) {
    tunslip_log("invalid IPv6 address '%s'", ipaddr);
    return;
  }
  tunslip_log("address %s => %02x%02x:%02x%02x:%02x%02x:%02x%02x",
              ipaddr,
              addr.s6_addr[0], addr.s6_addr[1],
              addr.s6_addr[2], addr.s6_addr[3],
              addr.s6_addr[4], addr.s6_addr[5],
              addr.s6_addr[6], addr.s6_addr[7]);
  slip_send('!');
  slip_send('P');
  for(int i = 0; i < 8; i++) {
    /* need to call slip_send_char for stuffing */
    slip_send_char(addr.s6_addr[i]);
  }
  slip_send(SLIP_END);
}
/*---------------------------------------------------------------------------*/
/* Write a received SLIP packet out to the tun interface. */
static void
deliver_packet(int outfd, const unsigned char *inbuf, size_t len)
{
  stats.rx_packets++;
  stats.rx_bytes += len;
  if(verbose > 2) {
    tunslip_log("packet from SLIP of length %zu - write TUN", len);
    if(verbose > 4) {
      print_packet_hex(inbuf, len);
    }
  }
  tunslip_write_packet(outfd, inbuf, len);
}
/*---------------------------------------------------------------------------*/
/* Echo received serial bytes to stdout according to the verbosity level. */
static void
echo_received_byte(unsigned char c, unsigned char *inbuf, size_t *inbufptr)
{
  /* Echo whole lines for verbose 2, 3, and 5+; echo printable chars for 4. */
  if(verbose == 2 || verbose == 3 || verbose > 4) {
    if(c == '\n' && is_sensible_string(inbuf, *inbufptr)) {
      stamptime(stdout);
      fwrite(inbuf, *inbufptr, 1, stdout);
      *inbufptr = 0;
    }
  } else if(verbose == 4) {
    if(c == 0 || c == '\r' || c == '\n' || c == '\t' || (c >= ' ' && c <= '~')) {
      fwrite(&c, 1, 1, stdout);
      if(c == '\n') {
        stamptime(stdout);
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
/*
 * Read from serial, when we have a packet write it to tun. No output
 * buffering, input buffered by stdio.
 */
static void
serial_to_tun(FILE *inslip, int outfd)
{
  static unsigned char inbuf[TUN_BUFSIZE];
  static size_t inbufptr;
  unsigned char c;
  bool first = true;

  while(1) {
    if(inbufptr >= sizeof(inbuf)) {
      stats.dropped_oversize++;
      tunslip_log("dropping large %zu byte packet", inbufptr);
      inbufptr = 0;
    }

    /*
     * serial_to_tun() runs only when select() reports the SLIP source
     * readable, so the first byte must be available: a zero-byte read on the
     * first iteration means the source has closed (EOF), and exiting avoids
     * spinning in the select() loop. A later zero-byte read just means stdio
     * has drained what it buffered, so return to select().
     */
    if(fread(&c, 1, 1, inslip) != 1) {
      if(first) {
        err(EXIT_FAILURE, "serial_to_tun: read");
      }
      clearerr(inslip);
      return;
    }
    first = false;

    progress(".");
    switch(c) {
    case SLIP_END:
      if(inbufptr > 0) {
        if(inbuf[0] == '?') {
          handle_prefix_request(inbuf, inbufptr);
        } else if(inbuf[0] == DEBUG_LINE_MARKER) {
          fwrite(inbuf + 1, inbufptr - 1, 1, stdout);
        } else if(is_sensible_string(inbuf, inbufptr)) {
          if(verbose == 1) {   /* strings already echoed below for verbose>1 */
            stamptime(stdout);
            fwrite(inbuf, inbufptr, 1, stdout);
          }
        } else {
          deliver_packet(outfd, inbuf, inbufptr);
        }
        inbufptr = 0;
      }
      break;

    case SLIP_ESC:
      if(fread(&c, 1, 1, inslip) != 1) {
        clearerr(inslip);
        /* Put ESC back and give up! */
        ungetc(SLIP_ESC, inslip);
        return;
      }

      switch(c) {
      case SLIP_ESC_END:
        c = SLIP_END;
        break;
      case SLIP_ESC_ESC:
        c = SLIP_ESC;
        break;
      case SLIP_ESC_XON:
        c = XON;
        break;
      case SLIP_ESC_XOFF:
        c = XOFF;
        break;
      }
    /* FALLTHROUGH */
    default:
      inbuf[inbufptr++] = c;
      echo_received_byte(c, inbuf, &inbufptr);
      break;
    }
  }
}
/*---------------------------------------------------------------------------*/
/*
 * The SLIP output buffer must hold the fully escaped encoding of a single
 * packet: in the worst case every byte is escaped into two bytes, plus a
 * trailing SLIP_END delimiter.
 */
static unsigned char slip_buf[2 * TUN_BUFSIZE + 1];
static size_t slip_end, slip_begin;
/*---------------------------------------------------------------------------*/
static void
slip_send_char(unsigned char c)
{
  switch(c) {
  case SLIP_END:
    slip_send(SLIP_ESC);
    slip_send(SLIP_ESC_END);
    break;
  case SLIP_ESC:
    slip_send(SLIP_ESC);
    slip_send(SLIP_ESC_ESC);
    break;
  case XON:
    if(flowcontrol_xonxoff) {
      slip_send(SLIP_ESC);
      slip_send(SLIP_ESC_XON);
    } else {
      slip_send(c);
    }
    break;
  case XOFF:
    if(flowcontrol_xonxoff) {
      slip_send(SLIP_ESC);
      slip_send(SLIP_ESC_XOFF);
    } else {
      slip_send(c);
    }
    break;
  default:
    slip_send(c);
    break;
  }
}
/*---------------------------------------------------------------------------*/
static void
slip_send(unsigned char c)
{
  if(slip_end >= sizeof(slip_buf)) {
    errx(EXIT_FAILURE, "slip_send overflow");
  }
  slip_buf[slip_end] = c;
  slip_end++;
}
/*---------------------------------------------------------------------------*/
static bool
slip_empty()
{
  return slip_end == 0;
}
/*---------------------------------------------------------------------------*/
static void
slip_flushbuf(int fd)
{
  if(slip_empty()) {
    return;
  }

  ssize_t n = write(fd, slip_buf + slip_begin, slip_end - slip_begin);

  if(n == -1 && errno != EAGAIN) {
    err(EXIT_FAILURE, "slip_flushbuf write failed");
  } else if(n == -1) {
    stats.queue_full++;
    progress("Q");    /* Outqueue is full! */
  } else {
    slip_begin += n;
    if(slip_begin == slip_end) {
      slip_begin = slip_end = 0;
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
write_to_serial(const void *inbuf, size_t len)
{
  const uint8_t *p = inbuf;

  stats.tx_packets++;
  stats.tx_bytes += len;

  if(verbose > 2) {
    tunslip_log("packet from TUN of length %zu - write SLIP", len);
    if(verbose > 4) {
      print_packet_hex(p, len);
    }
  }

  /* It would be ``nice'' to send a SLIP_END here but it's not
   * really necessary.
   */

  for(size_t i = 0; i < len; i++) {
    slip_send_char(p[i]);
  }
  slip_send(SLIP_END);
  progress("t");
}
/*---------------------------------------------------------------------------*/
/*
 * Read from tun, write to slip.
 */
static size_t
tun_to_serial(int infd)
{
  unsigned char inbuf[TUN_BUFSIZE];
  size_t size = tunslip_read_packet(infd, inbuf, sizeof(inbuf));

  write_to_serial(inbuf, size);
  return size;
}
/*---------------------------------------------------------------------------*/
static void
configure_tty(int fd)
{
  struct termios tty;
  speed_t speed = baud_speed;

  if(tcflush(fd, TCIOFLUSH) == -1) {
    err(EXIT_FAILURE, "tcflush");
  }

  if(tcgetattr(fd, &tty) == -1) {
    err(EXIT_FAILURE, "tcgetattr");
  }

  cfmakeraw(&tty);

  /* Nonblocking read. */
  tty.c_cc[VTIME] = 0;
  tty.c_cc[VMIN] = 0;
  if(flowcontrol) {
    tty.c_cflag |= CRTSCTS;
  } else {
    tty.c_cflag &= ~CRTSCTS;
  }
  tty.c_iflag &= ~IXON;
  if(flowcontrol_xonxoff) {
    tty.c_iflag |= IXOFF | IXANY;
  } else {
    tty.c_iflag &= ~IXOFF & ~IXANY;
  }
  tty.c_cflag &= ~HUPCL;
  tty.c_cflag &= ~CLOCAL;

  cfsetispeed(&tty, speed);
  cfsetospeed(&tty, speed);

  if(tcsetattr(fd, TCSAFLUSH, &tty) == -1) {
    err(EXIT_FAILURE, "tcsetattr");
  }

  tty.c_cflag |= CLOCAL;
  if(tcsetattr(fd, TCSAFLUSH, &tty) == -1) {
    err(EXIT_FAILURE, "tcsetattr");
  }

  int modem_bits = TIOCM_DTR;
  if(ioctl(fd, TIOCMBIS, &modem_bits) == -1) {
    err(EXIT_FAILURE, "ioctl");
  }

  usleep(10 * 1000);    /* Wait for hardware 10ms. */

  /* Flush input and output buffers. */
  if(tcflush(fd, TCIOFLUSH) == -1) {
    err(EXIT_FAILURE, "tcflush");
  }
}
/*---------------------------------------------------------------------------*/
int
devopen(const char *dev, int flags)
{
  /* "/dev/" plus a device name no longer than an interface name. */
  char t[sizeof("/dev/") + TUNDEV_SIZE];
  snprintf(t, sizeof(t), "/dev/%s", dev);
  return open(t, flags);
}
/*---------------------------------------------------------------------------*/
static volatile sig_atomic_t should_exit;
/*---------------------------------------------------------------------------*/
static void
sigcleanup(int signo)
{
  /*
   * Only record the signal here. Printing and exit() (which runs tunslip_cleanup(),
   * and therefore system()) are not async-signal-safe, so they are deferred
   * to the main loop.
   */
  should_exit = signo;
}
/*---------------------------------------------------------------------------*/
/* Dump accumulated traffic statistics through the tunslip6 message channel. */
static void
print_stats(void)
{
  tunslip_log("stats: SLIP->tun %llu packets, %llu bytes",
              stats.rx_packets, stats.rx_bytes);
  tunslip_log("stats: tun->SLIP %llu packets, %llu bytes",
              stats.tx_packets, stats.tx_bytes);
  tunslip_log("stats: %llu oversize drops, %llu output-queue-full events",
              stats.dropped_oversize, stats.queue_full);
}
/*---------------------------------------------------------------------------*/
static void
sigstats(int signo)
{
  (void)signo;   /* defer the dump to the main loop; just record the request */
  want_stats = 1;
}
/*---------------------------------------------------------------------------*/
static void
print_usage(const char *prog)
{
  fprintf(stderr, "usage:  %s [options] ipaddress\n", prog);
  fprintf(stderr, "example: tunslip6 -L -v2 -s ttyUSB1 fd00::1/64\n");
  fprintf(stderr, "Options are:\n");
#ifndef __APPLE__
  fprintf(stderr, " -B baudrate    9600,19200,38400,57600,115200 (default),230400,460800,921600\n");
#else
  fprintf(stderr, " -B baudrate    9600,19200,38400,57600,115200 (default),230400\n");
#endif
  fprintf(stderr, " -P             Show progress\n");
  fprintf(stderr, " -H             Hardware CTS/RTS flow control (default disabled)\n");
  fprintf(stderr, " -X             Software XON/XOFF flow control (default disabled)\n");
  fprintf(stderr, " -L             Log output format (adds time stamps)\n");
  fprintf(stderr, " -C when        Color own messages: auto (default), always, never\n");
  fprintf(stderr, " -q             Quiet: suppress tunslip6's own messages\n");
  fprintf(stderr, " -s siodev      Serial device (default /dev/ttyUSB0)\n");
  fprintf(stderr, " -M             Interface MTU (default and min: 1500)\n");
#ifdef __APPLE__
  fprintf(stderr, " -t tundev      Name of interface (default utun10)\n");
#else
  fprintf(stderr, " -t tundev      Name of interface (default tun0)\n");
#endif
#ifdef __APPLE__
  fprintf(stderr, " -v level       Verbosity level\n");
#else
  fprintf(stderr, " -v[level]      Verbosity level\n");
#endif
  fprintf(stderr, "    -v0         No messages\n");
  fprintf(stderr, "    -v1         Encapsulated SLIP debug messages\n");
  fprintf(stderr, "    -v2         Printable strings after they are received (default)\n");
  fprintf(stderr, "    -v3         Printable strings and SLIP packet notifications\n");
  fprintf(stderr, "    -v4         All printable characters as they are received\n");
  fprintf(stderr, "    -v5         All SLIP packets in hex\n");
#ifndef __APPLE__
  fprintf(stderr, "    -v          Equivalent to -v2\n");
#endif
#ifdef __APPLE__
  fprintf(stderr, " -d basedelay   Minimum delay between outgoing SLIP packets.\n");
#else
  fprintf(stderr, " -d[basedelay]  Minimum delay between outgoing SLIP packets.\n");
#endif
  fprintf(stderr, "                Actual delay is basedelay*(#6LowPAN fragments) milliseconds.\n");
#ifndef __APPLE__
  fprintf(stderr, "                -d is equivalent to -d10.\n");
#endif
  fprintf(stderr, " -a serveraddr  \n");
  fprintf(stderr, " -p serverport  \n");
}
/*---------------------------------------------------------------------------*/
/* Command-line options that are not stored in globals. */
struct options {
  const char *siodev;   /* serial device, or NULL to probe defaults */
  const char *host;     /* TCP server host, or NULL to use a serial device */
  const char *port;     /* TCP server port */
};
/*---------------------------------------------------------------------------*/
static void
parse_args(int argc, char **argv, struct options *opt)
{
  const char *prog = argv[0];
  int baudrate = -2;
  int c;

  opt->siodev = NULL;
  opt->host = NULL;
  opt->port = NULL;

  while((c = getopt(argc, argv, "B:C:HLPqhXM:s:t:v::d::a:p:")) != -1) {
    switch(c) {
    case 'B':
      baudrate = atoi(optarg);
      break;

    case 'H':
      flowcontrol = true;
      break;

    case 'X':
      flowcontrol_xonxoff = true;
      break;

    case 'L':
      timestamp = true;
      break;

    case 'C':
      if(strcmp(optarg, "auto") == 0) {
        color_mode = COLOR_AUTO;
      } else if(strcmp(optarg, "always") == 0) {
        color_mode = COLOR_ALWAYS;
      } else if(strcmp(optarg, "never") == 0) {
        color_mode = COLOR_NEVER;
      } else {
        errx(EXIT_FAILURE, "invalid -C value ``%s'' (use auto, always, or never)",
             optarg);
      }
      break;

    case 'M':
      devmtu = atoi(optarg);
      if(devmtu < MIN_DEVMTU) {
        devmtu = MIN_DEVMTU;
      }
      break;

    case 'P':
      showprogress = true;
      break;

    case 'q':
      quiet = true;
      break;

    case 's':
      if(strncmp("/dev/", optarg, 5) == 0) {
        opt->siodev = optarg + 5;
      } else {
        opt->siodev = optarg;
      }
      break;

    case 't':
      if(strncmp("/dev/", optarg, 5) == 0) {
        snprintf(tundev, sizeof(tundev), "%s", optarg + 5);
      } else {
        snprintf(tundev, sizeof(tundev), "%s", optarg);
      }
      break;

    case 'a':
      opt->host = optarg;
      break;

    case 'p':
      opt->port = optarg;
      break;

    case 'd':
      basedelay = 10;
      if(optarg) {
        basedelay = atoi(optarg);
      }
      break;

    case 'v':
      verbose = 2;
      if(optarg) {
        verbose = atoi(optarg);
      }
      break;

    case '?':
    case 'h':
    default:
      print_usage(prog);
      exit(EXIT_FAILURE);
    }
  }
  argc -= optind - 1;
  argv += optind - 1;

  if(argc != 2 && argc != 3) {
    errx(EXIT_FAILURE, "usage: %s [-B baudrate] [-P] [-q] [-H] [-X] [-L] [-C when] [-s siodev] [-M] [-t tundev] "
#ifdef __APPLE__
         "[-v level] [-d basedelay] "
#else
         "[-v [level]] [-d [basedelay]] "
#endif
         "[-a serveraddr] [-p serverport] ipaddress", prog);
  }
  ipaddr = argv[1];

  if(baudrate != -2) { /* -2: use default baudrate */
    baud_speed = select_baudrate(baudrate);
    if(baud_speed == 0) {
      errx(EXIT_FAILURE, "unknown baudrate %d", baudrate);
    }
  }

#ifdef __APPLE__
  if(*tundev == '\0') {
    /* utun0-3 are in use on Big Sur, so use utun10 as default */
    snprintf(tundev, sizeof(tundev), "utun10");
  }
#endif
}
/*---------------------------------------------------------------------------*/
static int
connect_to_server(const char *host, const char *port)
{
  struct addrinfo hints, *servinfo, *p;
  int rv, fd = -1;

  if(port == NULL) {
    port = "60001";
  }

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
    errx(EXIT_FAILURE, "getaddrinfo: %s", gai_strerror(rv));
  }

  /* loop through all the results and connect to the first we can */
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("client: socket");
      continue;
    }

    if(connect(fd, p->ai_addr, p->ai_addrlen) == -1) {
      perror("client: connect");
      close(fd);
      continue;
    }
    break;
  }

  if(p == NULL) {
    errx(EXIT_FAILURE, "can't connect to ``%s:%s''", host, port);
  }

  if(fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
    err(EXIT_FAILURE, "fcntl(F_SETFL, O_NONBLOCK)");
  }

  char s[INET6_ADDRSTRLEN];
  const char *addr_str = inet_ntop(p->ai_family, get_in_addr(p->ai_addr),
                                   s, sizeof(s));
  tunslip_log("slip connected to %s:%s",
              addr_str != NULL ? addr_str : "?", port);

  freeaddrinfo(servinfo);
  return fd;
}
/*---------------------------------------------------------------------------*/
static int
open_serial(const char *siodev)
{
  int fd;

  if(siodev != NULL) {
    fd = devopen(siodev, O_RDWR | O_NONBLOCK);
    if(fd == -1) {
      err(EXIT_FAILURE, "can't open siodev ``/dev/%s''", siodev);
    }
  } else {
    static const char *siodevs[] = {
      "ttyUSB0", "cuaU0", "ucom0" /* linux, fbsd6, fbsd5 */
    };
    fd = -1;
    for(int i = 0; i < 3; i++) {
      siodev = siodevs[i];
      fd = devopen(siodev, O_RDWR | O_NONBLOCK);
      if(fd != -1) {
        break;
      }
    }
    if(fd == -1) {
      err(EXIT_FAILURE, "can't open siodev");
    }
  }
  tunslip_log("SLIP started on /dev/%s", siodev);
  configure_tty(fd);
  return fd;
}
/*---------------------------------------------------------------------------*/
static void
setup_signal_handlers(void)
{
  atexit(tunslip_cleanup);
  signal(SIGHUP, sigcleanup);
  signal(SIGTERM, sigcleanup);
  signal(SIGINT, sigcleanup);
  signal(SIGUSR1, sigstats);
}
/*---------------------------------------------------------------------------*/
/* Clear the inter-packet delay once its configured interval has elapsed. */
static void
update_delay(void)
{
  struct timeval tv;

  if(!delaymsec) {
    return;
  }
  if(gettimeofday(&tv, NULL) == -1) {
    err(EXIT_FAILURE, "gettimeofday");
  }
  int dmsec = (int)((tv.tv_sec - delaystartsec) * 1000 + tv.tv_usec / 1000 - delaystartmsec);
  if(dmsec < 0 || dmsec > delaymsec) {
    delaymsec = 0;
  }
}
/*---------------------------------------------------------------------------*/
/* Read a packet from tun, SLIP-encode it, and arm the base delay if set. */
static void
forward_tun_to_serial(int tunfd)
{
  tun_to_serial(tunfd);
  slip_flushbuf(slipfd);
  if(basedelay) {
    struct timeval tv;
    if(gettimeofday(&tv, NULL) == -1) {
      err(EXIT_FAILURE, "gettimeofday");
    }
    delaymsec = basedelay;
    delaystartsec = tv.tv_sec;
    delaystartmsec = tv.tv_usec / 1000;
  }
}
/*---------------------------------------------------------------------------*/
static void
event_loop(FILE *inslip, int tunfd)
{
  fd_set rset, wset;

  while(1) {
    if(should_exit) {
      tunslip_log("caught signal %d, exiting", (int)should_exit);
      exit(EXIT_SUCCESS);      /* will call tunslip_cleanup() via atexit() */
    }

    if(want_stats) {           /* SIGUSR1 requested a stats dump */
      want_stats = 0;
      print_stats();
    }

    int maxfd = 0;
    FD_ZERO(&rset);
    FD_ZERO(&wset);

    if(!slip_empty()) {   /* Anything to flush? */
      FD_SET(slipfd, &wset);
    }

    FD_SET(slipfd, &rset);  /* Read from slip ASAP! */
    if(slipfd > maxfd) {
      maxfd = slipfd;
    }

    /* We only have one packet at a time queued for slip output. */
    if(slip_empty()) {
      FD_SET(tunfd, &rset);
      if(tunfd > maxfd) {
        maxfd = tunfd;
      }
    }

    int ret = select(maxfd + 1, &rset, &wset, NULL, NULL);
    if(ret == -1 && errno != EINTR) {
      err(EXIT_FAILURE, "select");
    } else if(ret > 0) {
      if(FD_ISSET(slipfd, &rset)) {
        serial_to_tun(inslip, tunfd);
      }

      if(FD_ISSET(slipfd, &wset)) {
        slip_flushbuf(slipfd);
      }

      /* Optional delay between outgoing packets: base delay times the
         number of 6LoWPAN fragments to be sent. */
      update_delay();
      if(delaymsec == 0 && slip_empty() && FD_ISSET(tunfd, &rset)) {
        forward_tun_to_serial(tunfd);
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
/* Resolve the -C color mode into the ANSI styling used by tunslip_log(). */
static void
init_log_style(void)
{
  bool enabled;

  switch(color_mode) {
  case COLOR_ALWAYS:
    enabled = true;
    break;
  case COLOR_NEVER:
    enabled = false;
    break;
  case COLOR_AUTO:
  default:
    /* Color a terminal only, and honor the NO_COLOR convention. */
    enabled = isatty(STDERR_FILENO) && getenv("NO_COLOR") == NULL;
    break;
  }

  if(enabled) {
    log_style = "\033[2m";      /* dim */
    log_style_reset = "\033[0m";
  }
}
/*---------------------------------------------------------------------------*/
int
main(int argc, char **argv)
{
  struct options opt;

  setvbuf(stdout, NULL, _IOLBF, 0); /* Line buffered output. */

  parse_args(argc, argv, &opt);
  init_log_style();

  if(opt.host != NULL) {
    slipfd = connect_to_server(opt.host, opt.port);
  } else {
    slipfd = open_serial(opt.siodev);
  }

  slip_send(SLIP_END);
  FILE *inslip = fdopen(slipfd, "r");
  if(inslip == NULL) {
    err(EXIT_FAILURE, "main: fdopen");
  }

  int tunfd = tunslip_open_tun(tundev, sizeof(tundev));
  if(tunfd == -1) {
    err(EXIT_FAILURE, "main: open /dev/tun");
  }
  tunslip_log("opened tun device /dev/%s", tundev);

  /* Registered before tunslip_cleanup so the stats line prints last at exit. */
  atexit(print_stats);
  setup_signal_handlers();
  tunslip_ifconf(tundev, ipaddr);

  event_loop(inslip, tunfd);
  return 0;
}
/*---------------------------------------------------------------------------*/
