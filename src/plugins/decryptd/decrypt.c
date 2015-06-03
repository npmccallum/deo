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

#include "decrypt.h"

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
             STACK_OF(DEO_KEY) *keys, ASN1_OCTET_STRING **key,
             EVP_PKEY **prv)
{
    if (infos == NULL || md == NULL || key == NULL || prv == NULL)
        return NULL;

    for (int i = 0; i < SKM_sk_num(DEO_KEY, keys); i++) {
        DEO_KEY *k = SKM_sk_value(DEO_KEY, keys, i);

        *prv = find_prv(infos, find_cert(infos, md, k->hash));
        if (*prv != NULL) {
            *key = k->key;
            return true;
        }
    }

    return false;
}

static ASN1_OCTET_STRING *
unseal(const EVP_CIPHER *cipher, ASN1_OCTET_STRING *key, EVP_PKEY *prv,
       DEO_MSG_DEC_REQ *dr)
{
    uint8_t buf[dr->data->length];
    ASN1_OCTET_STRING pt = {
        .type = V_ASN1_OCTET_STRING,
        .length = 0,
        .data = buf
    };
    AUTO(EVP_CIPHER_CTX, cctx);
    int len;

    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL)
        return NULL;

    if (EVP_OpenInit(cctx, cipher, key->data, key->length,
                     dr->iv->data, prv) != 1)
        return NULL;

    if (EVP_OpenUpdate(cctx, buf, &len, dr->data->data,
                       dr->data->length) != 1)
        return NULL;
    pt.length = len;

    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_TAG,
                            dr->tag->length, dr->tag->data) != 1)
        return NULL;

    if (EVP_OpenFinal(cctx, &buf[len], &len) != 1)
        return NULL;
    pt.length += len;

    return ASN1_OCTET_STRING_dup(&pt);
}

static const EVP_CIPHER *
load_cipher(DEO_MSG_DEC_REQ *dr)
{
    const EVP_CIPHER *cipher = NULL;

    switch (OBJ_obj2nid(dr->cipher)) {
    case NID_aes_128_gcm:
    case NID_aes_192_gcm:
    case NID_aes_256_gcm:
        if (EVP_GCM_TLS_TAG_LEN == dr->tag->length)
            break;

    default:
        return NULL;
    }

    cipher = EVP_get_cipherbyobj(dr->cipher);
    if (cipher == NULL)
        return NULL;

    if (EVP_CIPHER_iv_length(cipher) != dr->iv->length)
        return NULL;

    return cipher;
}

static const EVP_MD *
load_digest(DEO_MSG_DEC_REQ *dr)
{
    switch (OBJ_obj2nid(dr->digest)) {
    case NID_sha1:
    case NID_sha224:
    case NID_sha256:
    case NID_sha384:
    case NID_sha512:
        return EVP_get_digestbyobj(dr->digest);

    default:
        return NULL;
    }
}

DEO_ERR
decrypt(ctx *ctx, DEO_MSG_DEC_REQ *dr, ASN1_OCTET_STRING **pt)
{
    const EVP_CIPHER *cipher = NULL;
    const EVP_MD *digest = NULL;
    ASN1_OCTET_STRING *key = NULL;
    EVP_PKEY *prv = NULL;

    cipher = load_cipher(dr);
    if (cipher == NULL)
        return DEO_ERR_NOSUPPORT_CIPHER;

    digest = load_digest(dr);
    if (digest == NULL)
        return DEO_ERR_NOSUPPORT_DIGEST;

    if (!find_key_prv(ctx->dec, digest, dr->keys, &key, &prv))
        return DEO_ERR_NOTFOUND_KEY;

    *pt = unseal(cipher, key, prv, dr);
    return *pt == NULL ? DEO_ERR_INTERNAL : DEO_ERR_NONE;
}
