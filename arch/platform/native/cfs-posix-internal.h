/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden.
 * All rights reserved. SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CFS_POSIX_INTERNAL_H
#define CFS_POSIX_INTERNAL_H

#include <stdbool.h>

/*
 * Returns the working-directory fd that anchors all CFS file accesses.
 * The fd is opened lazily on first call. Returns -1 on failure.
 */
int cfs_posix_get_dirfd(void);

/*
 * Returns true iff the path is safe to use with openat()/unlinkat()
 * relative to the CFS dirfd: must be non-empty, relative (no leading
 * '/'), and must not contain any ".." component.
 */
bool cfs_posix_path_is_safe(const char *path);

#endif /* CFS_POSIX_INTERNAL_H */
