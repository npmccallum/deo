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

#include "encrypt.h"
#include "query.h"
#include "../main.h"
#include "../asn1.h"
#include "../d2i.h"

#include <openssl/err.h>
#include <openssl/rand.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <unistd.h>

#define PROCESS_BLOCK 4096

static int
make_targets(const STACK_OF(X509) *certs, STACK_OF(ASN1_UTF8STRING) *targets)
{
    for (int i = 0; i < sk_X509_num(certs); i++) {
        const ASN1_STRING *string = NULL;
        ASN1_UTF8STRING *target = NULL;
        X509_NAME_ENTRY *entry = NULL;
        X509 *cert = NULL;
        int idx;

        cert = sk_X509_value(certs, i);

        target = ASN1_UTF8STRING_new();
        if (target == NULL)
            return ENOMEM;

        if (sk_ASN1_UTF8STRING_push(targets, target) != 1) {
            ASN1_UTF8STRING_free(target);
            return ENOMEM;
        }

        idx = X509_NAME_get_index_by_NID(cert->cert_info->subject,
                                         NID_commonName, -1);
        if (idx < 0)
            return EINVAL;

        entry = X509_NAME_get_entry(cert->cert_info->subject, idx);
        if (entry == NULL)
            return EINVAL;

        string = X509_NAME_ENTRY_get_data(entry);
        if (string == NULL)
            return EINVAL;

        if (ASN1_STRING_set(target, string->data, string->length) != 1)
            return ENOMEM;
    }

    return 0;
}

static bool
make_dec_req(const EVP_CIPHER *cipher, const EVP_MD *md,
             const STACK_OF(X509) *certs, const uint8_t *key,
             PETERA_MSG_DEC_REQ *dr)
{
    uint8_t ct[cipher->key_len + EVP_CIPHER_block_size(cipher) - 1];
    uint8_t iv[EVP_CIPHER_iv_length(cipher)];
    uint8_t *ekeys[sk_X509_num(certs)];
    EVP_PKEY *keys[sk_X509_num(certs)];
    uint8_t tag[EVP_GCM_TLS_TAG_LEN];
    int ekeysl[sk_X509_num(certs)];
    AUTO(EVP_CIPHER_CTX, cctx);
    bool ret = false;
    int ctl = 0;
    int tmp = 0;

    ASN1_OBJECT_free(dr->cipher);
    ASN1_OBJECT_free(dr->digest);
    dr->cipher = OBJ_nid2obj(EVP_CIPHER_nid(cipher));
    dr->digest = OBJ_nid2obj(EVP_MD_type(md));
    if (dr->cipher == NULL || dr->digest == NULL)
        return false;

    for (size_t i = 0; i < sk_X509_num(certs); i++) {
        X509 *cert = sk_X509_value(certs, i);
        uint8_t digest[EVP_MAX_MD_SIZE];
        unsigned int dlen;
        PETERA_KEY *k;

        keys[i] = cert->cert_info->key->pkey;
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

        if (X509_digest(cert, md, digest, &dlen) != 1)
            goto error;

        if (ASN1_OCTET_STRING_set(k->hash, digest, dlen) != 1)
            goto error;
    }

    cctx = EVP_CIPHER_CTX_new();
    if (!cctx)
        return false;

    if (EVP_SealInit(cctx, cipher, ekeys, ekeysl,
                     iv, keys, sk_X509_num(certs)) != 1)
        goto error;

    if (ASN1_OCTET_STRING_set(dr->iv, iv, sizeof(iv)) != 1)
        goto error;

    for (int i = 0; i < SKM_sk_num(PETERA_KEY, dr->keys); i++) {
        PETERA_KEY *k = SKM_sk_value(PETERA_KEY, dr->keys, i);
        if (ASN1_OCTET_STRING_set(k->key, ekeys[i], ekeysl[i]) != 1)
            goto error;
    }

    if (EVP_SealUpdate(cctx, ct, &tmp, key, cipher->key_len) != 1)
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
    for (size_t i = 0; i < sk_X509_num(certs); i++)
        OPENSSL_free(ekeys[i]);

    return ret;
}

static PETERA_HEADER *
make_header(const STACK_OF(X509) *anchors, const STACK_OF(X509) *targets,
            const uint8_t *key)
{
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    const EVP_MD *md = EVP_sha256();
    uint8_t iv[EVP_MAX_IV_LENGTH];
    AUTO(PETERA_HEADER, hdr);

    if (cipher == NULL || md == NULL)
        return NULL;

    hdr = PETERA_HEADER_new();
    if (hdr == NULL)
        return EXIT_FAILURE;

    if (!make_dec_req(cipher, md, targets, key, hdr->req))
        return NULL;

    for (int i = 0; anchors != NULL && i < sk_X509_num(anchors); i++) {
        X509 *cert = X509_dup(sk_X509_value(anchors, i));
        if (cert == NULL)
            return false;

        if (sk_X509_push(hdr->anchors, cert) <= 0) {
            X509_free(cert);
            return false;
        }
    }

    if (make_targets(targets, hdr->targets) != 0)
        return NULL;

    if (RAND_bytes(iv, cipher->iv_len) != 1)
        return NULL;

    if (ASN1_OCTET_STRING_set(hdr->iv, iv, cipher->iv_len) != 1)
        return NULL;

    return STEAL(hdr);
}

static bool
encrypt_body(const PETERA_HEADER *hdr, const uint8_t *key, FILE *in, FILE *out)
{
    const EVP_CIPHER *cipher = EVP_get_cipherbyobj(hdr->req->cipher);
    uint8_t ct[PROCESS_BLOCK + EVP_MAX_BLOCK_LENGTH];
    uint8_t tag[EVP_GCM_TLS_TAG_LEN];
    AUTO(EVP_CIPHER_CTX, cctx);
    uint8_t pt[PROCESS_BLOCK];
    AUTO(SSL_CTX, ctx);
    size_t ptl;
    int ctl;

    if (ASN1_item_i2d_fp(&PETERA_HEADER_it, stdout, (void *) hdr) != 1)
        return false;

    cctx = EVP_CIPHER_CTX_new();
    if (!cctx)
        return false;

    if (EVP_EncryptInit_ex(cctx, cipher, NULL, key, hdr->iv->data) != 1)
        return false;

    while (!feof(stdin)) {
        ptl = fread(pt, 1, sizeof(pt), stdin);
        if (ferror(stdin))
            return false;

        ctl = 0;
        if (EVP_EncryptUpdate(cctx, ct, &ctl, pt, ptl) != 1)
            return false;

        if (fwrite(ct, 1, ctl, stdout) != (size_t) ctl)
            return false;
    }

    ctl = 0;
    if (EVP_EncryptFinal(cctx, ct, &ctl) != 1)
        return false;

    if (fwrite(ct, 1, ctl, stdout) != (size_t) ctl)
        return false;

    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG,
                            sizeof(tag), tag) != 1)
        return false;

    return fwrite(tag, 1, sizeof(tag), stdout) == sizeof(tag);
}


static STACK_OF(X509) *
parse_targets(const STACK_OF(X509) *anchors, size_t ntargets,
              const char *targets[])
{
    AUTO_STACK(X509, certs);

    certs = sk_X509_new_null();
    if (certs == NULL)
        return NULL;

    for (int i = 0; i < ntargets; i++) {
        AUTO_STACK(X509, chain);
        AUTO(FILE, fp);
        X509 *tmp;

        chain = sk_X509_new_null();
        if (chain == NULL)
            return NULL;

        fp = fopen(targets[i], "r");
        if (fp != NULL) {
            if (!load(anchors, fp, chain))
                return NULL;
        } else {
            if (!query(anchors, targets[i], chain))
                return NULL;
        }

        if (sk_X509_num(chain) == 0)
            return NULL;

        tmp = sk_X509_shift(chain);
        if (tmp == NULL)
            return NULL;

        if (sk_X509_push(certs, tmp) <= 0) {
            X509_free(tmp);
            return NULL;
        }
    }

    return STEAL(certs);
}

bool
encrypt(const STACK_OF(X509) *anchors, size_t ntargets, const char *targets[],
        FILE *in, FILE *out)
{
    uint8_t key[EVP_MAX_KEY_LENGTH];
    AUTO(PETERA_HEADER, hdr);
    AUTO_STACK(X509, certs);

    if (ntargets < 1)
        return EINVAL;

    certs = parse_targets(anchors, ntargets, targets);
    if (certs == NULL)
        return false;

    if (RAND_bytes(key, sizeof(key)) != 1)
        return false;

    hdr = make_header(anchors, certs, key);
    if (hdr == NULL)
        return EXIT_FAILURE;

    return encrypt_body(hdr, key, stdin, stdout);
}
