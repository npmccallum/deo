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

#include "c_decrypt.h"
#include "cleanup.h"
#include "d2i.h"
#include "common.h"

#include <openssl/err.h>

#include <stdbool.h>

int
cmd_decrypt(SSL_CTX *ctx, int argc, const char **argv)
{
    AUTO(PETERA_MSG_DEC_REQ, dr);
    bool success = false;

    dr = d2i_fp_max(&PETERA_MSG_DEC_REQ_it, stdin, NULL, PETERA_MAX_INPUT);
    if (dr == NULL) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    for (int i = 0; !success && i < argc; i++) {
        PETERA_ERR err = PETERA_ERR_NONE;
        AUTO(PETERA_MSG, in);
        AUTO(X509, cert);
        AUTO(BIO, io);

        io = BIO_new_ssl_connect(ctx);
        if (io == NULL)
            return EXIT_FAILURE;

        BIO_set_conn_port(io, PETERA_DEF_PORT);
        BIO_set_ssl_mode(io, SSL_MODE_AUTO_RETRY);
        if (BIO_set_conn_hostname(io, argv[i]) <= 0)
            return EXIT_FAILURE;

        if (BIO_do_connect(io) <= 0)
            continue;

        if (BIO_do_handshake(io) <= 0)
            continue;

        if (ASN1_item_i2d_bio(&PETERA_MSG_it, io, &(PETERA_MSG) {
                .type = PETERA_MSG_TYPE_DEC_REQ,
                .value.dec_req = dr
            }) <= 0)
            return EXIT_FAILURE;

        in = ASN1_item_d2i_bio(&PETERA_MSG_it, io, NULL);
        if (in == NULL)
            continue;

        switch (in->type) {
        case PETERA_MSG_TYPE_ERR:
            err = ASN1_ENUMERATED_get(in->value.err);
            fprintf(stderr, "Server error: %s!\n", petera_err_string(err));
            break;

        case PETERA_MSG_TYPE_DEC_REP:
            fwrite(in->value.dec_rep->data, 1,
                   in->value.dec_rep->length, stdout);
            success = true;
            break;

        default:
            fprintf(stderr, "Invalid response!\n");
            break;
        }
    }

    if (!success) {
        fprintf(stderr, "No server could decrypt this data!\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
