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

#define _GNU_SOURCE
#include "decrypt.h"
#include "../../d2i.h"
#include "../../main.h"

#include <openssl/err.h>
#include <systemd/sd-daemon.h>

#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

static bool
option(char c, const char *arg, const char **misc)
{
    *misc = arg;
    return true;
}

static ctx *
load_ctx(int argc, char *argv[])
{
    const char *tlsfile = NULL;
    const char *encfile = NULL;
    const char *decdir = NULL;
    ctx *ctx;

    if (!deo_getopt(argc, argv, "ht:e:d:", "", NULL, NULL,
                    option, &tlsfile, option, &encfile, option, &decdir))
        goto usage;

    if (tlsfile == NULL || encfile == NULL || decdir == NULL)
        goto usage;

    ctx = ctx_init(tlsfile, encfile, decdir);
    if (ctx != NULL)
        return ctx;

usage:
    fprintf(stderr, "Usage: deo decryptd "
            "-t <tlsfile> -e <encfile> -d <decdir>\n");
    return NULL;
}

static BIO *
start_tls(SSL_CTX *ctx)
{
    AUTO(BIO, sio);
    SSL *ssl;

    sio = BIO_new_ssl(ctx, 0);
    if (sio == NULL)
        return NULL;

    if (BIO_get_ssl(sio, &ssl) <= 0)
        return NULL;

    if (SSL_set_fd(ssl, SD_LISTEN_FDS_START) <= 0)
        return NULL;

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    return STEAL(sio);
}

static int
decryptd(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    AUTO(DEO_MSG, in);
    AUTO(BIO, sio);
    AUTO(ctx, ctx);

    ctx = load_ctx(argc, argv);
    if (ctx == NULL)
        goto error;

    sio = start_tls(ctx->ctx);
    if (sio == NULL)
        goto error;

    in = d2i_bio_max(&DEO_MSG_it, sio, NULL, DEO_MAX_INPUT);
    if (in == NULL)
        goto error;

    switch (in->type) {
    case DEO_MSG_TYPE_CRT_REQ:
        ASN1_item_i2d_bio(&DEO_MSG_it, sio, &(DEO_MSG) {
            .type = DEO_MSG_TYPE_CRT_REP,
            .value.crt_rep = ctx->crt
        });
        break;

    case DEO_MSG_TYPE_DEC_REQ: {
        DEO_ERR err = DEO_ERR_NONE;
        AUTO(ASN1_OCTET_STRING, pt);

        err = decrypt(ctx, in->value.dec_req, &pt);
        if (err != DEO_ERR_NONE) {
            SEND_ERR(sio, err);
            break;
        }

        ASN1_item_i2d_bio(&DEO_MSG_it, sio, &(DEO_MSG) {
            .type = DEO_MSG_TYPE_DEC_REP,
            .value.dec_rep = pt
        });
        break;
    }

    default:
        break;
    }

    ret = EXIT_SUCCESS;

error:
    if (ret != EXIT_SUCCESS)
        ERR_print_errors_fp(stderr);

    return ret;
}

deo_plugin deo = { decryptd, NULL };
