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

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#define DECLARE_CLEANUP(type) \
    void cleanup_ ## type(type **x)

#define DEFINE_CLEANUP(type) \
    void cleanup_ ## type(type **x) { \
        if (x == NULL || *x == NULL) return; \
        type ## _free(*x); \
    }


#define DECLARE_CLEANUP_STACK(type) \
    void cleanup_sk_ ## type(STACK_OF(type) **x)

#define DEFINE_CLEANUP_STACK(type) \
    void cleanup_sk_ ## type(STACK_OF(type) **x) { \
        if (x == NULL || *x == NULL) return; \
        sk_ ## type ## _pop_free(*x, type ## _free); \
    }

#define AUTO(type, name) \
    __attribute__((cleanup(cleanup_ ## type))) type *name = NULL

#define AUTO_FD(name) \
    __attribute__((cleanup(cleanup_fd))) int name = -1

#define AUTO_STACK(type, name) \
    __attribute__((cleanup(cleanup_sk_ ## type))) STACK_OF(type) *name = NULL

#define STEAL(name) \
    ({ __typeof__(name) __tmp = name; name = NULL; __tmp; })

DECLARE_CLEANUP(uint8_t);
DECLARE_CLEANUP(char);
DECLARE_CLEANUP(FILE);
DECLARE_CLEANUP(DIR);

void
cleanup_fd(int *fd);

DECLARE_CLEANUP_STACK(X509_INFO);
DECLARE_CLEANUP_STACK(X509);

DECLARE_CLEANUP(ASN1_OCTET_STRING);
DECLARE_CLEANUP(EVP_CIPHER_CTX);
DECLARE_CLEANUP(EVP_PKEY);
DECLARE_CLEANUP(X509_STORE_CTX);
DECLARE_CLEANUP(X509_STORE);
DECLARE_CLEANUP(X509);
DECLARE_CLEANUP(SSL_CTX);
DECLARE_CLEANUP(SSL);
DECLARE_CLEANUP(BIO);
DECLARE_CLEANUP(BIGNUM);
