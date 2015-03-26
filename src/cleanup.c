/*
 * Copyright (c) 2015 Red Hat, Inc.
 * Author: Nathaniel McCallum <npmccallum@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "cleanup.h"
#include <unistd.h>
#include <stdlib.h>

void
cleanup_uint8_t(uint8_t **x)
{
    if (x == NULL) return;
    free(*x);
}

void
cleanup_char(char **x)
{
    if (x == NULL) return;
    free(*x);
}

void
cleanup_FILE(FILE **x)
{
    if (x == NULL || *x == NULL) return;
    fclose(*x);
}

void
cleanup_DIR(DIR **x)
{
    if (x == NULL || *x == NULL) return;
    closedir(*x);
}

void
cleanup_fd(int *fd)
{
    if (fd == NULL || *fd < 0)
        return;

    close(*fd);
}
