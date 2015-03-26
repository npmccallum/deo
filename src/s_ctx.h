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

#include "cleanup.h"

#include <openssl/x509.h>

typedef struct {
    SSL_CTX *ctx;
    STACK_OF(X509) *crt;
    STACK_OF(X509_INFO) *dec;
} ctx;

void
ctx_free(ctx *ctx);

ctx *
ctx_init(const char *tls, const char *enc, const char *dec);

DECLARE_CLEANUP(ctx);
