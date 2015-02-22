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

#include "s_decrypt.h"

#include <stdbool.h>

static EVP_PKEY *
find_prv(STACK_OF(X509_INFO) *infos, X509 *cert)
{
    if (infos == NULL || cert == NULL)
        return NULL;

    for (int i = 0; i < sk_X509_INFO_num(infos); i++) {
        X509_INFO *info = sk_X509_INFO_value(infos, i);

        if (info->x_pkey == NULL)
            continue;

        if (X509_check_private_key(cert, info->x_pkey->dec_pkey) == 1)
            return info->x_pkey->dec_pkey;
    }

    return NULL;
}

static X509 *
find_cert(STACK_OF(X509_INFO) *infos, const EVP_MD *md,
          ASN1_OCTET_STRING *hash)
{
    if (infos == NULL || md == NULL || hash == NULL)
        return NULL;

    for (int i = 0; i < sk_X509_INFO_num(infos); i++) {
        X509_INFO *info = sk_X509_INFO_value(infos, i);
        uint8_t digest[EVP_MD_size(md)];
        unsigned int dlen;

        if (info->x509 == NULL)
            continue;

        if (X509_digest(info->x509, md, digest, &dlen) <= 0)
            return NULL;

        if ((int) dlen != hash->length)
            continue;

        if (memcmp(digest, hash->data, dlen) != 0)
            continue;

        return info->x509;
    }

    return NULL;
}

static bool
find_key_prv(STACK_OF(X509_INFO) *infos, const EVP_MD *md,
             STACK_OF(PETERA_KEY) *keys, ASN1_OCTET_STRING **key,
             EVP_PKEY **prv)
{
    if (infos == NULL || md == NULL || key == NULL || prv == NULL)
        return NULL;

    for (int i = 0; i < SKM_sk_num(PETERA_KEY, keys); i++) {
        PETERA_KEY *k = SKM_sk_value(PETERA_KEY, keys, i);

        *prv = find_prv(infos, find_cert(infos, md, k->hash));
        if (*prv != NULL) {
            *key = k->key;
            return true;
        }
    }

    return false;
}

static PETERA_PLAINTEXT *
unseal(const EVP_CIPHER *cipher, ASN1_OCTET_STRING *key, EVP_PKEY *prv,
       PETERA_CIPHERTEXT *ct)
{
    AUTO(EVP_CIPHER_CTX, cctx);
    uint8_t buf[ct->data->length];
    int bufl;
    int len;

    if (EVP_CIPHER_iv_length(cipher) != ct->iv->length)
        return NULL;

    /* Perform decryption. */
    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL)
        return NULL;

    if (EVP_OpenInit(cctx, cipher, key->data, key->length,
                     ct->iv->data, prv) != 1)
        return NULL;

    if (EVP_OpenUpdate(cctx, buf, &len, ct->data->data,
                       ct->data->length) != 1)
        return NULL;
    bufl = len;

    if (EVP_OpenFinal(cctx, &buf[len], &len) != 1)
        return NULL;
    bufl += len;

    return d2i_PETERA_PLAINTEXT(NULL, &(const uint8_t *) { buf }, bufl);
}

PETERA_ERR
decrypt(ctx *ctx, PETERA_MSG_DEC_REQ *dr, PETERA_PLAINTEXT **pt)
{
    const EVP_CIPHER *cipher = NULL;
    const EVP_MD *digest = NULL;
    ASN1_OCTET_STRING *key = NULL;
    EVP_PKEY *prv = NULL;

    cipher = EVP_get_cipherbyobj(dr->parameters->cipher);
    if (cipher == NULL)
        return PETERA_ERR_NOSUPPORT_CIPHER;

    digest = EVP_get_digestbyobj(dr->parameters->digest);
    if (digest == NULL)
        return PETERA_ERR_NOSUPPORT_DIGEST;

    if (!find_key_prv(ctx->dec, digest, dr->ciphertext->keys, &key, &prv))
        return PETERA_ERR_NOTFOUND_KEY;

    *pt = unseal(cipher, key, prv, dr->ciphertext);
    return *pt == NULL ? PETERA_ERR_INTERNAL : PETERA_ERR_NONE;
}
