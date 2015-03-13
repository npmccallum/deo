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

static bool
decrypt(PETERA_HEADER *hdr, ASN1_OCTET_STRING *key)
{
    const EVP_CIPHER *cipher = NULL;
    AUTO(EVP_CIPHER_CTX, cctx);
    uint8_t ct[4096];
    size_t tlen = 0;

    if (!hdr || !key)
        return false;

    cipher = EVP_get_cipherbyobj(hdr->req->cipher);
    if (cipher == NULL)
        return false;

    switch (EVP_CIPHER_nid(cipher)) {
    case NID_aes_128_gcm:
    case NID_aes_192_gcm:
    case NID_aes_256_gcm:
        tlen = EVP_GCM_TLS_TAG_LEN;
        break;

    default:
        return false;
    }

    if (cipher->iv_len != hdr->iv->length)
        return false;

    if (key->length < cipher->key_len)
        return false;

    cctx = EVP_CIPHER_CTX_new();
    if (!cctx)
        return false;

    if (EVP_DecryptInit_ex(cctx, cipher, NULL,
                           key->data, hdr->iv->data) != 1)
        return false;

    for (size_t ctl = 0; !feof(stdin); ) {
        uint8_t pt[sizeof(ct) + EVP_MAX_BLOCK_LENGTH];
        int ptl = 0;

        ctl += fread(ct + ctl, 1, sizeof(ct) - ctl, stdin);
        if (ferror(stdin))
            return false;

        if (ctl < tlen) {
            if (feof(stdin))
                return false;
            continue;
        }

        ptl = 0;
        if (EVP_DecryptUpdate(cctx, pt, &ptl, ct, ctl - tlen) != 1)
            return false;

        memmove(ct, ct + ctl - tlen, tlen);
        ctl = tlen;

        if (feof(stdin)) {
            int tmp = 0;

            if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_TAG,
                                    tlen, ct) != 1)
                return false;

            if (EVP_DecryptFinal_ex(cctx, pt + ptl, &tmp) != 1)
                return false;

            ptl += tmp;
        }

        if (fwrite(pt, 1, ptl, stdout) != (size_t) ptl)
            return false;
    }

    return true;
}

int
cmd_decrypt(SSL_CTX *ctx, int argc, const char **argv)
{
    AUTO(PETERA_HEADER, hdr);
    bool success = false;

    hdr = d2i_fp_max(&PETERA_HEADER_it, stdin, NULL, PETERA_MAX_INPUT);
    if (hdr == NULL) {
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
                .value.dec_req = hdr->req
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
            success = decrypt(hdr, in->value.dec_rep);
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
