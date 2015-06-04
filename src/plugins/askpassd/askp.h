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

#pragma once

#include <poll.h>
#include <stdbool.h>

#include "list.h"

struct askp;

int
askp_new(struct askp **ctx, struct pollfd *fd);

bool
askp_question(struct askp *ctx, struct pollfd *fd);

void
askp_process(struct askp *ctx, char *argv[], const char *keysdir);

bool
askp_more(struct askp *ctx);

void
askp_free(struct askp *ctx);
