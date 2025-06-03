/*
 * Copyright (c) 2025, RISE Research Institutes of Sweden AB
 * All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *	System call stubs for Newlib-nano.
 */

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

/*---------------------------------------------------------------------------*/
int
_open(const char *file, int flags, int mode)
{
  (void)file;
  (void)flags;
  (void)mode;
  return -1;
}
/*---------------------------------------------------------------------------*/
int
_close(int fd)
{
  (void)fd;
  return -1;
}
/*---------------------------------------------------------------------------*/
off_t
_lseek(int var, off_t pos, int whence)
{
  (void)var;
  (void)pos;
  (void)whence;
  return (off_t)-1;
}
/*---------------------------------------------------------------------------*/
long
_read(int fd, void *buf, size_t cnt)
{
  (void)fd;
  (void)buf;
  (void)cnt;
  return -1;
}
/*---------------------------------------------------------------------------*/
long
_write(int fd, const void *buf, size_t cnt)
{
  (void)fd;
  (void)buf;
  (void)cnt;
  return -1;
}
/*---------------------------------------------------------------------------*/
int
_kill(pid_t pid, int sig)
{
  (void)pid;
  (void)sig;
  return -1;
}
/*---------------------------------------------------------------------------*/
int
_isatty(int fd)
{
  return 0;
}
/*---------------------------------------------------------------------------*/
int
_getpid(void)
{
  return -1;
}
/*---------------------------------------------------------------------------*/
int
_fstat(int fd, struct stat *statbuf)
{
  (void)fd;
  (void)statbuf;
  return -1;
}
/*---------------------------------------------------------------------------*/
