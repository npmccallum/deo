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

DEFINE_CLEANUP_STACK(X509_INFO)
DEFINE_CLEANUP_STACK(X509)

DEFINE_CLEANUP(ASN1_OCTET_STRING)
DEFINE_CLEANUP(EVP_CIPHER_CTX)
DEFINE_CLEANUP(EVP_PKEY)
DEFINE_CLEANUP(X509_STORE_CTX)
DEFINE_CLEANUP(X509_STORE)
DEFINE_CLEANUP(X509)
DEFINE_CLEANUP(SSL_CTX)
DEFINE_CLEANUP(SSL)

void
cleanup_BIO(BIO **x) {
    if (x == NULL) return;
    BIO_free_all(*x);
}

void
cleanup_BIGNUM(BIGNUM **x) {
    if (x == NULL) return;
    BN_free(*x);
}

DEFINE_CLEANUP(PETERA_MSG_DEC_REQ)
DEFINE_CLEANUP(PETERA_MSG)
DEFINE_CLEANUP(PETERA_HEADER)

void
cleanup_uint8_t(uint8_t **x)
{
    if (x == NULL) return;
    OPENSSL_free(*x);
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
