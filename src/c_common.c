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

#include "c_common.h"
#include "cleanup.h"
#include "common.h"

#include <openssl/err.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

bool
validate_chain(SSL_CTX *ctx, STACK_OF(X509) *certs)
{
    AUTO(X509_STORE_CTX, sctx);
    X509_STORE *store;

    if (certs == NULL || sk_X509_num(certs) == 0)
        return false;

    store = SSL_CTX_get_cert_store(ctx);
    if (store == NULL)
        return false;

    sctx = X509_STORE_CTX_new();
    if (sctx == NULL)
        return false;

    if (X509_STORE_CTX_init(sctx, store, sk_X509_value(certs, 0), certs) <= 0)
        return false;

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

SSL_CTX *
make_ssl_ctx(const char *anchor)
{
    AUTO(SSL_CTX, ctx);
    struct stat st;

    ctx = SSL_CTX_new(TLSv1_2_client_method());
    if (ctx == NULL)
        return NULL;

    if (lstat(anchor, &st) != 0) {
        fprintf(stderr, "Anchor: %s\n", strerror(errno));
        return NULL;
    }

    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Anchor: invalid file type\n");
        return NULL;
    }

    if (S_ISREG(st.st_mode)
        && SSL_CTX_load_verify_locations(ctx, anchor, NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (S_ISDIR(st.st_mode)
        && SSL_CTX_load_verify_locations(ctx, NULL, anchor) <= 0) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return STEAL(ctx);
}
