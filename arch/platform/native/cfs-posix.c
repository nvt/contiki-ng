/*
 * Copyright (c) 2004, Swedish Institute of Computer Science.
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
 *
 * This file is part of the Contiki operating system.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdbool.h>
#ifdef _MSC_VER
#include <io.h>
#else
#include <unistd.h>
#endif

#include "cfs/cfs.h"
#include "cfs-posix-internal.h"

/*
 * The CFS POSIX backend used to pass caller-supplied paths straight to
 * open()/remove(), which made every CFS user a path-traversal sink for
 * whatever subsystem fed the path (Coffee, LWM2M, OSCORE state, etc.).
 *
 * We now anchor all CFS file access at the process working directory at
 * the time of first use, opened once as a directory fd, and use openat()
 * so the kernel resolves names relative to that fd. Names are also
 * checked: absolute paths are rejected, and any ".." component is
 * rejected. O_NOFOLLOW prevents symlink-based escapes through entries
 * inside the working directory.
 */

static int cfs_dirfd = -1;

int
cfs_posix_get_dirfd(void)
{
  if(cfs_dirfd < 0) {
    cfs_dirfd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  }
  return cfs_dirfd;
}

bool
cfs_posix_path_is_safe(const char *path)
{
  if(path == NULL || path[0] == '\0' || path[0] == '/') {
    return false;
  }
  const char *p = path;
  while(*p != '\0') {
    /* p is at the start of a component. */
    if(p[0] == '.' && p[1] == '.' && (p[2] == '\0' || p[2] == '/')) {
      return false;
    }
    while(*p != '\0' && *p != '/') {
      p++;
    }
    while(*p == '/') {
      p++;
    }
  }
  return true;
}

/*---------------------------------------------------------------------------*/
int
cfs_open(const char *n, int f)
{
  int s = 0;

  if(!cfs_posix_path_is_safe(n) || cfs_posix_get_dirfd() < 0) {
    return -1;
  }

  if(f == CFS_READ) {
    return openat(cfs_posix_get_dirfd(), n, O_RDONLY | O_NOFOLLOW);
  } else if(f & CFS_WRITE) {
    s = O_CREAT | O_NOFOLLOW;
    if(f & CFS_READ) {
      s |= O_RDWR;
    } else {
      s |= O_WRONLY;
    }
    if(f & CFS_APPEND) {
      s |= O_APPEND;
    } else {
      s |= O_TRUNC;
    }
    return openat(cfs_posix_get_dirfd(), n, s, 0600);
  }
  return -1;
}
/*---------------------------------------------------------------------------*/
void
cfs_close(int f)
{
  close(f);
}
/*---------------------------------------------------------------------------*/
int
cfs_read(int f, void *b, unsigned int l)
{
  return read(f, b, l);
}
/*---------------------------------------------------------------------------*/
int
cfs_write(int f, const void *b, unsigned int l)
{
  return write(f, b, l);
}
/*---------------------------------------------------------------------------*/
cfs_offset_t
cfs_seek(int f, cfs_offset_t o, int w)
{
  if(w == CFS_SEEK_SET) {
    w = SEEK_SET;
  } else if(w == CFS_SEEK_CUR) {
    w = SEEK_CUR;
  } else if(w == CFS_SEEK_END) {
    w = SEEK_END;
  } else {
    return (cfs_offset_t)-1;
  }
  return lseek(f, o, w);
}
/*---------------------------------------------------------------------------*/
int
cfs_remove(const char *name)
{
  if(!cfs_posix_path_is_safe(name) || cfs_posix_get_dirfd() < 0) {
    return -1;
  }
  return unlinkat(cfs_posix_get_dirfd(), name, 0);
}
/*---------------------------------------------------------------------------*/
