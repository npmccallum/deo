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
#include "d2i.h"
#include "common.h"

#include <openssl/err.h>
#include <openssl/rand.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <unistd.h>

static bool
seal(const EVP_CIPHER *cipher, const EVP_MD *md, const X509 **certs,
     size_t ncerts, uint8_t *data, size_t dlen, PETERA_MSG_DEC_REQ *dr)
{
    uint8_t ct[dlen + EVP_CIPHER_block_size(cipher) - 1];
    uint8_t iv[EVP_CIPHER_iv_length(cipher)];
    uint8_t tag[EVP_GCM_TLS_TAG_LEN];
    AUTO(EVP_CIPHER_CTX, cctx);
    uint8_t *ekeys[ncerts];
    EVP_PKEY *keys[ncerts];
    int ekeysl[ncerts];
    AUTO(uint8_t, key);

    bool ret = false;
    int ctl = 0;
    int tmp = 0;

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

        if (SKM_sk_push(PETERA_KEY, dr->keys, k) != 1) {
            PETERA_KEY_free(k);
            goto error;
        }

        if (X509_digest(certs[i], md, digest, &dlen) != 1)
            goto error;

        if (ASN1_OCTET_STRING_set(k->hash, digest, dlen) != 1)
            goto error;
    }

    cctx = EVP_CIPHER_CTX_new();
    if (!cctx)
        return false;

    if (EVP_SealInit(cctx, cipher, ekeys, ekeysl, iv, keys, ncerts) != 1)
        goto error;

    if (ASN1_OCTET_STRING_set(dr->iv, iv, sizeof(iv)) != 1)
        goto error;

    for (int i = 0; i < SKM_sk_num(PETERA_KEY, dr->keys); i++) {
        PETERA_KEY *k = SKM_sk_value(PETERA_KEY, dr->keys, i);
        if (ASN1_OCTET_STRING_set(k->key, ekeys[i], ekeysl[i]) != 1)
            goto error;
    }

    if (EVP_SealUpdate(cctx, ct, &tmp, data, dlen) != 1)
        goto error;
    ctl = tmp;

    if (EVP_SealFinal(cctx, ct + ctl, &tmp) != 1)
        goto error;
    ctl += tmp;

    if (ASN1_OCTET_STRING_set(dr->data, ct, ctl) != 1)
        goto error;

    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG,
                            sizeof(tag), tag) != 1)
        goto error;

    if (ASN1_OCTET_STRING_set(dr->tag, tag, sizeof(tag)) != 1)
        goto error;

    ret = true;

error:
    for (size_t i = 0; i < ncerts; i++)
        OPENSSL_free(ekeys[i]);

    return ret;
}

static STACK_OF(X509) *
load_chain(SSL_CTX *ctx, const char *location, FILE *fp)
{
    AUTO_STACK(X509_INFO, infos);
    AUTO_STACK(X509, chain);

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

static bool
make_key(SSL_CTX *ctx, const EVP_CIPHER *cipher, const EVP_MD *digest,
         int argc, const char **argv, STACK_OF(ASN1_UTF8STRING) *targets,
         PETERA_MSG_DEC_REQ *dr, uint8_t *key)
{
    STACK_OF(X509) *chains[argc];
    const X509 *certs[argc];
    bool ret = false;

    memset(chains, 0, sizeof(chains));
    memset(certs, 0, sizeof(certs));

    if (!cipher || !digest || !argv || !dr || !key)
        return false;

    if (RAND_bytes(key, cipher->key_len) != 1)
        return false;

    for (int i = 0; i < argc; i++) {
        ASN1_UTF8STRING *target = NULL;
        AUTO(FILE, fp);

        fp = fopen(argv[i], "r");
        if (fp == NULL)
            chains[i] = fetch_chain(ctx, argv[i]);
        else
            chains[i] = load_chain(ctx, argv[i], fp);
        if (chains[i] == NULL)
            goto error;

        certs[i] = sk_value((_STACK*) chains[i], 0);
        if (certs[i] == NULL)
            goto error;

        target = ASN1_UTF8STRING_new();
        if (target == NULL)
            goto error;

        if (sk_ASN1_UTF8STRING_push(targets, target) != 1) {
            ASN1_UTF8STRING_free(target);
            goto error;
        }

        if (fp == NULL) {
            if (ASN1_STRING_set(target, argv[i], strlen(argv[i])) != 1)
                goto error;
        } else {
            X509_NAME_ENTRY *entry;
            ASN1_STRING *string;
            int idx;

            idx = X509_NAME_get_index_by_NID(certs[i]->cert_info->subject,
                                             NID_commonName, -1);
            if (idx < 0)
                goto error;

            entry = X509_NAME_get_entry(certs[i]->cert_info->subject, idx);
            if (entry == NULL)
                goto error;

            string = X509_NAME_ENTRY_get_data(entry);
            if (string == NULL)
                goto error;

            if (ASN1_STRING_set(target, string->data, string->length) != 1)
                goto error;
        }
    }

    ASN1_OBJECT_free(dr->cipher);
    ASN1_OBJECT_free(dr->digest);
    dr->cipher = OBJ_nid2obj(EVP_CIPHER_nid(cipher));
    dr->digest = OBJ_nid2obj(EVP_MD_type(digest));
    if (dr->cipher == NULL || dr->digest == NULL)
        return false;

    ret = seal(cipher, digest, certs, argc, key, cipher->key_len, dr);

error:
    for (int i = 0; i < argc; i++)
        SKM_sk_pop_free(X509, chains[i], X509_free);

    ERR_print_errors_fp(stderr);
    return ret;
}

int
cmd_encrypt(int argc, const char **argv)
{
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    const EVP_MD *digest = EVP_sha256();
    AUTO(EVP_CIPHER_CTX, cctx);
    AUTO(PETERA_HEADER, hdr);
    AUTO(SSL_CTX, ctx);

    uint8_t tag[EVP_GCM_TLS_TAG_LEN];
    uint8_t key[EVP_MAX_KEY_LENGTH];
    uint8_t iv[EVP_MAX_IV_LENGTH];
    uint8_t pt[4096];
    uint8_t ct[sizeof(pt) + EVP_MAX_BLOCK_LENGTH];

    size_t ptl;
    int ctl;

    if (argc < 2)
        return EINVAL;

    ctx = make_ssl_ctx(argv[0]);
    if (ctx == NULL)
        return EXIT_FAILURE;

    if (cipher == NULL || digest == NULL) {
        fprintf(stderr, "Unable to initialize crypto!\n");
        return EXIT_FAILURE;
    }

    hdr = PETERA_HEADER_new();
    if (hdr == NULL)
        return EXIT_FAILURE;

    if (!make_key(ctx, cipher, digest, argc - 1, &argv[1],
                  hdr->targets, hdr->req, key))
        return EXIT_FAILURE;

    if (RAND_bytes(iv, cipher->iv_len) != 1)
        return EXIT_FAILURE;

    if (ASN1_OCTET_STRING_set(hdr->iv, iv, cipher->iv_len) != 1)
        return EXIT_FAILURE;

    if (ASN1_item_i2d_fp(&PETERA_HEADER_it, stdout, hdr) != 1)
        return EXIT_FAILURE;

    cctx = EVP_CIPHER_CTX_new();
    if (!cctx)
        return EXIT_FAILURE;

    if (EVP_EncryptInit_ex(cctx, cipher, NULL, key, iv) != 1)
        return EXIT_FAILURE;

    while (!feof(stdin)) {
        ptl = fread(pt, 1, sizeof(pt), stdin);
        if (ferror(stdin))
            return EXIT_FAILURE;

        ctl = 0;
        if (EVP_EncryptUpdate(cctx, ct, &ctl, pt, ptl) != 1)
            return EXIT_FAILURE;

        if (fwrite(ct, 1, ctl, stdout) != (size_t) ctl)
            return EXIT_FAILURE;
    }

    ctl = 0;
    if (EVP_EncryptFinal(cctx, ct, &ctl) != 1)
        return EXIT_FAILURE;

    if (fwrite(ct, 1, ctl, stdout) != (size_t) ctl)
        return EXIT_FAILURE;

    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG,
                            sizeof(tag), tag) != 1)
        return EXIT_FAILURE;

    if (fwrite(tag, 1, sizeof(tag), stdout) != sizeof(tag))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
