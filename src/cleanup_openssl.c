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

#include "cleanup_openssl.h"

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
