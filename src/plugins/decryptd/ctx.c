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

#include "ctx.h"
#include "../cleanup.h"
#include "../misc.h"

#include <openssl/err.h>

static STACK_OF(X509_INFO) *
load_decryption_certs_keys(const char *dirname)
{
    AUTO_STACK(X509_INFO, infos);
    AUTO(DIR, dir);

    if (dirname == NULL)
        return NULL;

    infos = sk_X509_INFO_new_null();
    if (infos == NULL)
        return NULL;

    dir = opendir(dirname);
    if (dir == NULL)
        return NULL;

    for (struct dirent *de = readdir(dir); de != NULL; de = readdir(dir)) {
        char path[strlen(dirname) + strlen(de->d_name) + 2];
        AUTO(FILE, file);

        if (!deo_isreg(dirname, de))
            continue;

        strcpy(path, dirname);
        strcat(path, "/");
        strcat(path, de->d_name);

        file = fopen(path, "r");
        if (file == NULL)
            return NULL;

        if (PEM_X509_INFO_read(file, infos, NULL, NULL) == NULL)
            return NULL;
    }

    if (sk_X509_INFO_num(infos) == 0)
        return NULL;

    return STEAL(infos);
}

static EVP_PKEY *
load_prv(const char *filename)
{
    AUTO(BIO, bio);

    bio = BIO_new_file(filename, "r");
    if (bio == NULL)
        return NULL;

    return PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
}

static void
ctx_free(ctx *ctx)
{
    if (ctx == NULL)
        return;

    sk_X509_INFO_pop_free(ctx->dec, X509_INFO_free);
    sk_X509_pop_free(ctx->crt, X509_free);
    SSL_CTX_free(ctx->ctx);
    OPENSSL_free(ctx);
}

ctx *
ctx_init(const char *tls, const char *enc, const char *dec)
{
    AUTO(EVP_PKEY, prv);
    AUTO(FILE, file);
    AUTO(ctx, ctx);

    if (tls == NULL || enc == NULL || dec == NULL)
        return NULL;

    ctx = OPENSSL_malloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));

    ctx->ctx = SSL_CTX_new(TLSv1_2_server_method());
    if (ctx->ctx == NULL)
        return NULL;

    if (SSL_CTX_use_certificate_chain_file(ctx->ctx, tls) <= 0)
        return NULL;

    prv = load_prv(tls);
    if (prv == NULL)
        return NULL;

    if (SSL_CTX_use_PrivateKey(ctx->ctx, prv) <= 0)
        return NULL;

    file = fopen(enc, "r");
    if (file == NULL)
        return NULL;

    ctx->crt = sk_X509_new_null();
    if (ctx->crt == NULL)
        return NULL;

    if (!deo_load(file, ctx->crt))
        return NULL;

    ctx->dec = load_decryption_certs_keys(dec);
    if (ctx->dec == NULL)
        return NULL;

    /* Check to ensure that the TLS connection key is not also listed
     * in the decryption keys. This prevents an attack where, upon
     * misconfiguration, this service could be used to decrypt its own
     * traffic. */
    for (int i = 0; i < sk_X509_INFO_num(ctx->dec); i++) {
        X509_INFO *info = sk_X509_INFO_value(ctx->dec, i);

        if (info->x_pkey == NULL)
            continue;

        if (EVP_PKEY_cmp(prv, info->x_pkey->dec_pkey) == 1) {
            fprintf(stderr, "TLS private key is exposed!\n");
            return NULL;
        }
    }

    return STEAL(ctx);
}

DEFINE_CLEANUP(ctx)
