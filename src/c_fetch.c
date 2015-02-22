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

#include "c_fetch.h"
#include "cleanup.h"
#include "common.h"

#include <openssl/err.h>

#include <stdbool.h>
#include <errno.h>

bool
validate_chain(SSL_CTX *ctx, STACK_OF(X509) *certs)
{
    AUTO(X509_STORE_CTX, sctx);
    X509_STORE *store;

    if (certs == NULL || sk_X509_num(certs) == 0)
        return NULL;

    store = SSL_CTX_get_cert_store(ctx);
    if (store == NULL)
        return NULL;

    sctx = X509_STORE_CTX_new();
    if (sctx == NULL)
        return NULL;

    if (X509_STORE_CTX_init(sctx, store, sk_X509_value(certs, 0), certs) <= 0)
        return NULL;

    return X509_verify_cert(sctx) > 0;
}

STACK_OF(X509) *
fetch_chain(SSL_CTX *ctx, const char *host_port)
{
    PETERA_ERR err = PETERA_ERR_NONE;
    AUTO(PETERA_MSG, in);
    AUTO(BIO, io);

    io = BIO_new_ssl_connect(ctx);
    if (io == NULL)
        return NULL;

    BIO_set_conn_port(io, PETERA_DEF_PORT);
    BIO_set_ssl_mode(io, SSL_MODE_AUTO_RETRY);
    if (BIO_set_conn_hostname(io, host_port) <= 0)
        return NULL;

    if (BIO_do_connect(io) <= 0)
        return NULL;

    if (BIO_do_handshake(io) <= 0)
        return NULL;

    if (ASN1_item_i2d_bio(&PETERA_MSG_it, io, &(PETERA_MSG) {
            .type = PETERA_MSG_TYPE_CRT_REQ,
            .value.crt_req = &(ASN1_NULL) {0}
        }) <= 0)
        return NULL;

    in = ASN1_item_d2i_bio(&PETERA_MSG_it, io, NULL);
    if (in == NULL)
        return NULL;

    switch (in->type) {
    case PETERA_MSG_TYPE_ERR:
        err = ASN1_ENUMERATED_get(in->value.err);
        fprintf(stderr, "Server error: %s!\n", petera_err_string(err));
        return NULL;

    case PETERA_MSG_TYPE_CRT_REP:
        break;

    default:
        fprintf(stderr, "Invalid response!\n");
        return NULL;
    }

    if (!validate_chain(ctx, in->value.crt_rep)) {
        fprintf(stderr, "Remote encryption certificate is untrusted!\n");
        return NULL;
    }

    return STEAL(in->value.crt_rep);
}

int
cmd_fetch(SSL_CTX *ctx, int argc, const char **argv)
{
    AUTO_STACK(X509, certs);

    if (argc != 1)
        return EINVAL;

    certs = fetch_chain(ctx, argv[0]);
    if (certs == NULL) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    for (int i = 0; i < sk_X509_num(certs); i++)
        PEM_write_X509(stdout, sk_X509_value(certs, i));

    return 0;
}
