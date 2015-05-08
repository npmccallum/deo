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

#include "../main.h"
#include "../d2i.h"
#include "query.h"

bool
decrypt(const STACK_OF(X509) *anchors, size_t ntargets, const char *targets[],
        FILE *in, FILE *out)
{
    const EVP_CIPHER *cipher = NULL;
    AUTO(ASN1_OCTET_STRING, key);
    AUTO(EVP_CIPHER_CTX, cctx);
    AUTO(PETERA_HEADER, hdr);
    uint8_t ct[4096];
    size_t tlen = 0;

    hdr = d2i_fp_max(&PETERA_HEADER_it, in, NULL, PETERA_MAX_INPUT);
    if (hdr == NULL)
        return false;

    /* Add specified anchors to the embedded anchors. */
    for (int i = sk_X509_num(anchors) - 1; anchors != NULL && i >= 0 ; i--) {
        X509 *cert = X509_dup(sk_X509_value(anchors, i));
        if (cert == NULL)
            return false;

        if (sk_X509_unshift(hdr->anchors, cert) <= 0) {
            X509_free(cert);
            return false;
        }
    }

    /* Add specified targets to the embedded targets. */
    for (int i = ntargets - 1; i >= 0; i--) {
        ASN1_UTF8STRING *target = ASN1_UTF8STRING_new();
        if (target == NULL)
            return false;

        if (sk_ASN1_UTF8STRING_unshift(hdr->targets, target) <= 0) {
            ASN1_UTF8STRING_free(target);
            return false;
        }

        if (ASN1_STRING_set(target, targets[i], strlen(targets[i])) != 1)
            return false;
    }

    /* Decrypt the key. */
    for (size_t i = 0; i < sk_ASN1_UTF8STRING_num(hdr->targets); i++) {
        ASN1_UTF8STRING *trgt = sk_ASN1_UTF8STRING_value(hdr->targets, i);
        AUTO(PETERA_MSG, rep);

        rep = request(hdr->anchors, trgt, &(PETERA_MSG) {
            .type = PETERA_MSG_TYPE_DEC_REQ,
            .value.dec_req = hdr->req
        });

        if (rep != NULL && rep->type == PETERA_MSG_TYPE_DEC_REP) {
            key = STEAL(rep->value.dec_rep);
            break;
        }
    }
    if (key == NULL)
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

        ctl += fread(ct + ctl, 1, sizeof(ct) - ctl, in);
        if (ferror(in))
            return false;

        if (ctl < tlen) {
            if (feof(in))
                return false;
            continue;
        }

        ptl = 0;
        if (EVP_DecryptUpdate(cctx, pt, &ptl, ct, ctl - tlen) != 1)
            return false;

        memmove(ct, ct + ctl - tlen, tlen);
        ctl = tlen;

        if (feof(in)) {
            int tmp = 0;

            if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_TAG,
                                    tlen, ct) != 1)
                return false;

            if (EVP_DecryptFinal_ex(cctx, pt + ptl, &tmp) != 1)
                return false;

            ptl += tmp;
        }

        if (fwrite(pt, 1, ptl, out) != (size_t) ptl)
            return false;
    }

    return true;
}
