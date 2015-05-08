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

#include "query.h"
#include "../main.h"

#include <openssl/err.h>

static bool
validate(const STACK_OF(X509) *anchors, STACK_OF(X509) *certs)
{
    AUTO(X509_STORE_CTX, sctx);
    AUTO(X509_STORE, store);

    if (certs == NULL || sk_X509_num(certs) == 0)
        return false;

    if (anchors == NULL)
        return true;

    store = X509_STORE_new();
    if (store == NULL)
        return false;

    if (sk_X509_num(anchors) == 0) {
        if (X509_STORE_set_default_paths(store) <= 0)
            return false;
    } else {
        for (int i = 0; i < sk_X509_num(anchors); i++) {
            X509 *cert = sk_X509_value(anchors, i);
            X509_STORE_add_cert(store, cert);
        }
    }

    sctx = X509_STORE_CTX_new();
    if (sctx == NULL)
        return false;

    if (X509_STORE_CTX_init(sctx, store, sk_X509_value(certs, 0), certs) <= 0)
        return false;

    return X509_verify_cert(sctx) > 0;
}

bool
load(const STACK_OF(X509) *anchors, FILE *fp, STACK_OF(X509) *certs)
{
    AUTO_STACK(X509_INFO, infos);

    infos = PEM_X509_INFO_read(fp, NULL, NULL, NULL);
    if (infos == NULL)
        return false;

    for (int i = 0; i < sk_X509_INFO_num(infos); i++) {
        X509_INFO *info = sk_X509_INFO_value(infos, i);
        X509 *cert;

        if (info->x509 == NULL)
            continue;

        cert = X509_dup(info->x509);
        if (cert == NULL)
            return false;

        if (sk_X509_push(certs, cert) <= 0) {
            X509_free(cert);
            return false;
        }
    }

    if (!validate(anchors, certs))
        return false;

    return true;
}

PETERA_MSG *
request(const STACK_OF(X509) *anchors, const ASN1_UTF8STRING *target,
        const PETERA_MSG *req)
{
    PETERA_ERR err = PETERA_ERR_NONE;
    char trgt[target->length + 1];
    AUTO(SSL_CTX, ctx);
    AUTO(BIO, io);

    memset(trgt, 0, sizeof(trgt));
    memcpy(trgt, target->data, target->length);

    if (anchors == NULL)
        return NULL;

    ctx = SSL_CTX_new(TLSv1_2_client_method());
    if (ctx == NULL)
        return NULL;

    if (sk_X509_num(anchors) == 0) {
        if (X509_STORE_set_default_paths(SSL_CTX_get_cert_store(ctx)) <= 0)
            return NULL;
    } else {
        for (int i = 0; anchors != NULL && i < sk_X509_num(anchors); i++) {
            X509 *cert = sk_X509_value(anchors, i);
            X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), cert);
        }
    }

    io = BIO_new_ssl_connect(ctx);
    if (io == NULL)
        return NULL;

    BIO_set_conn_port(io, PETERA_SOCKET);
    BIO_set_ssl_mode(io, SSL_MODE_AUTO_RETRY);
    if (BIO_set_conn_hostname(io, trgt) <= 0)
        return NULL;

    if (BIO_do_connect(io) <= 0)
        return NULL;

    if (BIO_do_handshake(io) <= 0)
        return NULL;

    if (ASN1_item_i2d_bio(&PETERA_MSG_it, io, (PETERA_MSG *) req) <= 0)
        return NULL;

    return ASN1_item_d2i_bio(&PETERA_MSG_it, io, NULL);
}

bool
query(const STACK_OF(X509) *anchors, const char *target,
      STACK_OF(X509) *certs)
{
    PETERA_ERR err = PETERA_ERR_NONE;
    AUTO(PETERA_MSG, rep);
    AUTO(FILE, fp);

    rep = request(anchors, &(ASN1_UTF8STRING) {
        .data = (char *) target,
        .length = strlen(target)
    }, &(PETERA_MSG) {
        .type = PETERA_MSG_TYPE_CRT_REQ,
        .value.crt_req = &(ASN1_NULL) {0}
    });

    if (rep == NULL) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    switch (rep->type) {
    case PETERA_MSG_TYPE_ERR:
        err = ASN1_ENUMERATED_get(rep->value.err);
        fprintf(stderr, "Server error: %s!\n", petera_err_string(err));
        return false;

    case PETERA_MSG_TYPE_CRT_REP:
        if (!validate(anchors, rep->value.crt_rep)) {
            fprintf(stderr, "Certificate validation failed! (%s)\n", target);
            return false;
        }

        while (sk_X509_num(rep->value.crt_rep) > 0) {
            X509 *cert = sk_X509_pop(rep->value.crt_rep);
            if (cert == NULL)
                return false;

            if (sk_X509_unshift(certs, cert) <= 0) {
                X509_free(cert);
                return false;
            }
        }

        return true;

    default:
        fprintf(stderr, "Invalid response!\n");
        return false;
    }
}
