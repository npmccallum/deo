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

#include <openssl/err.h>
#include <openssl/rand.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <error.h>
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
             DEO_MSG_DEC_REQ *dr)
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

    for (int i = 0; i < sk_X509_num(certs); i++) {
        X509 *cert = sk_X509_value(certs, i);
        uint8_t digest[EVP_MAX_MD_SIZE];
        unsigned int dlen;
        DEO_KEY *k;

        keys[i] = cert->cert_info->key->pkey;
        ekeys[i] = OPENSSL_malloc(EVP_PKEY_size(keys[i]));
        if (ekeys[i] == NULL)
            goto error;

        k = DEO_KEY_new();
        if (k == NULL)
            goto error;

        if (SKM_sk_push(DEO_KEY, dr->keys, k) != 1) {
            DEO_KEY_free(k);
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

    for (int i = 0; i < SKM_sk_num(DEO_KEY, dr->keys); i++) {
        DEO_KEY *k = SKM_sk_value(DEO_KEY, dr->keys, i);
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
    for (int i = 0; i < sk_X509_num(certs); i++)
        OPENSSL_free(ekeys[i]);

    return ret;
}

static DEO_HEADER *
make_header(const STACK_OF(X509) *anchors, const STACK_OF(X509) *targets,
            const uint8_t *key)
{
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    const EVP_MD *md = EVP_sha256();
    uint8_t iv[EVP_MAX_IV_LENGTH];
    AUTO(DEO_HEADER, hdr);

    if (cipher == NULL || md == NULL)
        return NULL;

    hdr = DEO_HEADER_new();
    if (hdr == NULL)
        return NULL;

    if (!make_dec_req(cipher, md, targets, key, hdr->req))
        return NULL;

    for (int i = 0; anchors != NULL && i < sk_X509_num(anchors); i++) {
        X509 *cert = X509_dup(sk_X509_value(anchors, i));
        if (cert == NULL)
            return NULL;

        if (sk_X509_push(hdr->anchors, cert) <= 0) {
            X509_free(cert);
            return NULL;
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
encrypt_body(const DEO_HEADER *hdr, const uint8_t *key, FILE *in, FILE *out)
{
    const EVP_CIPHER *cipher = EVP_get_cipherbyobj(hdr->req->cipher);
    uint8_t ct[PROCESS_BLOCK + EVP_MAX_BLOCK_LENGTH];
    uint8_t tag[EVP_GCM_TLS_TAG_LEN];
    AUTO(EVP_CIPHER_CTX, cctx);
    uint8_t pt[PROCESS_BLOCK];
    size_t ptl;
    int ctl;

    if (ASN1_item_i2d_fp(&DEO_HEADER_it, stdout, (void *) hdr) != 1)
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

static int
encrypt(int argc, char *argv[])
{
    uint8_t key[EVP_MAX_KEY_LENGTH];
    AUTO_STACK(X509, anchors);
    AUTO(DEO_HEADER, hdr);
    AUTO_STACK(X509, certs);

    if (!deo_getopt(argc, argv, "ha:", "", NULL, NULL,
                       deo_anchors, &anchors)
        || sk_X509_num(anchors) == 0 || argc - optind < 1) {
        fprintf(stderr, "Usage: deo encrypt "
                        "-a <anchors> <target> [...] "
                        "< PLAINTEXT > CIPHERTEXT\n");
        return EXIT_FAILURE;
    }

    certs = sk_X509_new_null();
    if (certs == NULL)
        error(EXIT_FAILURE, ENOMEM, "Unable to create anchors");

    for (int i = optind; i < argc; i++) {
        AUTO_STACK(X509, chain);
        AUTO(FILE, fp);
        X509 *tmp;

        fp = fopen(argv[i], "r");
        if (fp != NULL) {
            chain = sk_X509_new_null();
            if (chain == NULL)
                error(EXIT_FAILURE, ENOMEM, "Unable to create anchors chain");

            if (!deo_load(fp, chain))
                error(EXIT_FAILURE, 0, "Unable to load anchors");
        } else {
            AUTO(DEO_MSG, rep);

            rep = deo_request(anchors, &(ASN1_UTF8STRING) {
                .data = (uint8_t *) argv[i],
                .length = strlen(argv[i])
            }, &(DEO_MSG) {
                .type = DEO_MSG_TYPE_CRT_REQ,
                .value.crt_req = &(ASN1_NULL) {0}
            });

            if (rep == NULL)
                error(EXIT_FAILURE, 0, "Unable to communicate with server");

            switch (rep->type) {
            case DEO_MSG_TYPE_CRT_REP:
                if (!deo_validate(anchors, rep->value.crt_rep))
                    error(EXIT_FAILURE, 0, "Server returned untrusted certs");

                chain = STEAL(rep->value.crt_rep);
                break;

            case DEO_MSG_TYPE_ERR:
                error(EXIT_FAILURE, ENOMEM, "Server returned: %s",
                      deo_err_string(ASN1_ENUMERATED_get(rep->value.err)));

            default:
                error(EXIT_FAILURE, 0, "Received unknown message from server");
            }
        }

        if (sk_X509_num(chain) == 0)
            error(EXIT_FAILURE, 0, "Server returned no certs");

        tmp = sk_X509_shift(chain);
        if (sk_X509_push(certs, tmp) <= 0) {
            X509_free(tmp);
            error(EXIT_FAILURE, ENOMEM, "Unable to add target certificate");
        }
    }

    if (RAND_bytes(key, sizeof(key)) != 1)
        error(EXIT_FAILURE, ENOMEM, "Unable to generate random key");

    hdr = make_header(anchors, certs, key);
    if (hdr == NULL)
        error(EXIT_FAILURE, ENOMEM, "Error building header");

    if (!encrypt_body(hdr, key, stdin, stdout))
        error(EXIT_FAILURE, 0, "Failure encrypting message body");

    return 0;
}

deo_plugin deo = {
    encrypt, "Encrypts input to all specified targets"
};
