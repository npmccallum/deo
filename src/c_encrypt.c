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

#include "c_encrypt.h"
#include "c_fetch.h"
#include "cleanup.h"
#include "d2i.h"
#include "common.h"

#include <openssl/err.h>
#include <openssl/rand.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <unistd.h>

static PETERA_PLAINTEXT *
get_plaintext(const EVP_CIPHER *cipher, FILE *fp)
{
    AUTO(PETERA_PLAINTEXT, pt);

    uint8_t conf[EVP_CIPHER_block_size(cipher)];
    uint8_t input[PETERA_MAX_INPUT / 2];
    int inputl;

    pt = PETERA_PLAINTEXT_new();
    if (pt == NULL)
        return NULL;

    inputl = fread(input, 1, sizeof(input), fp);
    if (input == 0 || inputl == sizeof(input))
        return NULL;

    if (ASN1_OCTET_STRING_set(pt->plaintext, input, inputl) <= 0)
        return NULL;

    if (RAND_bytes(conf, sizeof(conf)) <= 0)
        return NULL;

    if (ASN1_OCTET_STRING_set(pt->confounder, conf, sizeof(conf)) <= 0)
        return NULL;

    return STEAL(pt);
}

static bool
seal(const EVP_CIPHER *cipher, const EVP_MD *md,
     X509 **certs, size_t ncerts, PETERA_PLAINTEXT *ppt,
     PETERA_CIPHERTEXT *pct)
{
    AUTO(EVP_CIPHER_CTX, cctx);
    AUTO(uint8_t, key);
    AUTO(uint8_t, pt);
    AUTO(uint8_t, ct);

    uint8_t iv[EVP_CIPHER_iv_length(cipher)];
    uint8_t *ekeys[ncerts];
    EVP_PKEY *keys[ncerts];
    int ekeysl[ncerts];
    bool ret = false;
    int ptl = 0;
    int ctl = 0;
    int tmp = 0;

    ptl = i2d_PETERA_PLAINTEXT(ppt, &pt);
    if (pt == NULL)
        goto error;

    for (size_t i = 0; i < ncerts; i++) {
        uint8_t digest[EVP_MAX_MD_SIZE];
        unsigned int dlen;
        PETERA_KEY *k;

        keys[i] = certs[i]->cert_info->key->pkey;
        ekeys[i] = OPENSSL_malloc(EVP_PKEY_size(keys[i]));
        if (ekeys[i] == NULL)
            goto error;

        k = PETERA_KEY_new();
        if (k == NULL)
            goto error;

        if (SKM_sk_push(PETERA_KEY, pct->keys, k) <= 0) {
            PETERA_KEY_free(k);
            goto error;
        }

        if (X509_digest(certs[i], md, digest, &dlen) <= 0)
            goto error;

        if (ASN1_OCTET_STRING_set(k->hash, digest, dlen) <= 0)
            goto error;
    }

    ct = OPENSSL_malloc(ptl + EVP_CIPHER_block_size(cipher) - 1);
    if (ct == NULL)
        goto error;

    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL)
        goto error;

    if (EVP_SealInit(cctx, cipher, ekeys, ekeysl, iv, keys, ncerts) <= 0)
        goto error;

    if (ASN1_OCTET_STRING_set(pct->iv, iv, sizeof(iv)) <= 0)
        goto error;

    for (int i = 0; i < SKM_sk_num(PETERA_KEY, pct->keys); i++) {
        PETERA_KEY *k = SKM_sk_value(PETERA_KEY, pct->keys, i);
        if (ASN1_OCTET_STRING_set(k->key, ekeys[i], ekeysl[i]) <= 0)
            goto error;
    }

    if (EVP_SealUpdate(cctx, ct, &tmp, pt, ptl) <= 0)
        goto error;
    ctl = tmp;

    if (EVP_SealFinal(cctx, ct + ctl, &tmp) <= 0)
        goto error;
    ctl += tmp;

    if (ASN1_OCTET_STRING_set(pct->data, ct, ctl) <= 0)
        goto error;

    ret = true;

error:
    for (size_t i = 0; i < ncerts; i++)
        OPENSSL_free(ekeys[i]);

    return ret;
}

static PETERA_MSG_DEC_REQ *
prepare(const EVP_CIPHER **cipher, const EVP_MD **digest)
{
    AUTO(PETERA_MSG_DEC_REQ, dr);

    *cipher = EVP_aes_128_cbc();
    *digest = EVP_sha224();
    if (*cipher == NULL || *digest == NULL)
        return NULL;

    dr = PETERA_MSG_DEC_REQ_new();
    if (dr == NULL)
        return NULL;

    ASN1_OBJECT_free(dr->parameters->cipher);
    ASN1_OBJECT_free(dr->parameters->digest);
    dr->parameters->cipher = OBJ_nid2obj(EVP_CIPHER_nid(*cipher));
    dr->parameters->digest = OBJ_nid2obj(EVP_MD_type(*digest));
    if (dr->parameters->cipher == NULL || dr->parameters->digest == NULL)
        return NULL;

    return STEAL(dr);
}

static STACK_OF(X509) *
load_chain(SSL_CTX *ctx, const char *location)
{
    AUTO_STACK(X509_INFO, infos);
    AUTO_STACK(X509, chain);
    AUTO(FILE, fp);

    fp = fopen(location, "r");
    if (fp == NULL)
        return fetch_chain(ctx, location);

    infos = PEM_X509_INFO_read(fp, NULL, NULL, NULL);
    if (infos == NULL)
        return NULL;

    chain = sk_X509_new_null();
    if (chain == NULL)
        return NULL;

    for (int i = 0; i < sk_X509_INFO_num(infos); i++) {
        X509_INFO *info = sk_X509_INFO_value(infos, i);
        X509 *cert;

        if (info->x509 == NULL)
            continue;

        cert = X509_dup(info->x509);
        if (cert == NULL)
            return NULL;

        if (sk_X509_push(chain, cert) <= 0) {
            X509_free(cert);
            return NULL;
        }
    }

    if (!validate_chain(ctx, chain)) {
        fprintf(stderr, "Certificate validation failed! (%s)\n", location);
        return NULL;
    }

    return STEAL(chain);
}

int
cmd_encrypt(SSL_CTX *ctx, int argc, const char **argv)
{
    AUTO(PETERA_MSG_DEC_REQ, dr);
    AUTO(PETERA_PLAINTEXT, pt);

    const EVP_CIPHER *cipher = NULL;
    const EVP_MD *digest = NULL;
    int ret = EXIT_FAILURE;
    X509 *certs[argc];

    STACK_OF(X509) *chains[argc];

    memset(chains, 0, sizeof(chains));
    memset(certs, 0, sizeof(certs));

    dr = prepare(&cipher, &digest);
    if (dr == NULL)
        goto error;

    pt = get_plaintext(cipher, stdin);
    if (pt == NULL)
        goto error;

    for (int i = 0 ; i < argc; i++) {
        chains[i] = load_chain(ctx, argv[i]);
        if (chains[i] == NULL)
            goto error;

        certs[i] = sk_value((_STACK*) chains[i], 0);
        if (certs[i] == NULL)
            goto error;
    }

    if (!seal(cipher, digest, certs, argc, pt, dr->ciphertext))
        goto error;

    if (ASN1_item_i2d_fp(&PETERA_MSG_DEC_REQ_it, stdout, dr) <= 0)
        goto error;

    ret = EXIT_SUCCESS;

error:
    for (int i = 0; i < argc; i++)
        SKM_sk_pop_free(X509, chains[i], X509_free);

    ERR_print_errors_fp(stderr);
    return ret;
}
