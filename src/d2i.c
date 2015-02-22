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

#include "d2i.h"
#include "cleanup.h"

#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

#define BLOCKSIZE 128

#define BIT8 0b10000000

#define IS_ID_SHORT(b) \
    (((b) & V_ASN1_PRIMITIVE_TAG) != V_ASN1_PRIMITIVE_TAG)

#define IS_ID_LAST(b) \
    (((b) & BIT8) == 0)

#define IS_LEN_SHORT(b) \
    (((b) & BIT8) == 0)

static ssize_t
get_size(const uint8_t *buf, size_t len, BIGNUM *out)
{
    int sz = -1;

    if (len == 0)
        return 1;

    if (BN_set_word(out, 0) <= 0)
        return -ENOMEM;

    for (size_t i = 0; i < len; i++) {
        if (sz > 0) {
            if (BN_lshift(out, out, 8) <= 0)
                return -ENOMEM;

            if (BN_add_word(out, buf[i]) <= 0)
                return -ENOMEM;
        } else if (sz < 0) {
            if (i == 0) {
                if (IS_ID_SHORT(buf[i]))
                    sz++;
            } else if (IS_ID_LAST(buf[i]))
                sz++;
        } else if (sz == 0) {
            sz = buf[i] & ~BIT8;

            if (IS_LEN_SHORT(buf[i]))
                return BN_set_word(out, sz) > 0 ? 0 : -ENOMEM;

            if (i + 1 == len)
                return sz;
        }
    }

    return sz <= 0 ? 1 : 0;
}

void *
d2i_bio_max(const ASN1_ITEM *it, BIO *in, void *x, unsigned int max)
{
    AUTO(uint8_t, buf);
    AUTO(BIGNUM, size);
    AUTO(BIGNUM, cmp);
    size_t blocks = 0;
    ssize_t need = 0;
    size_t have = 0;
    int rd;

    size = BN_new();
    if (size == NULL)
        return NULL;

    while (true) {
        need = get_size(buf, have, size);
        if (need < 0)
            return NULL;
        else if (need == 0)
            break;

        if (have + need > max)
            return NULL;

        if (have + (size_t) need >= blocks * BLOCKSIZE) {
            uint8_t *tmp;

            blocks = (have + need + BLOCKSIZE - 1) / BLOCKSIZE;
            tmp = OPENSSL_realloc(buf, blocks * BLOCKSIZE);
            if (tmp == NULL)
                return NULL;

            buf = tmp;
        }

        rd = BIO_read(in, buf + have, need);
        have += need;
        if (rd <= 0 || rd != need)
            return NULL;
    }

    cmp = BN_new();
    if (cmp == NULL)
        return NULL;

    if (BN_set_word(cmp, max) <= 0)
        return NULL;

    if (BN_cmp(size, cmp) > 0)
        return NULL;

    if (BN_set_word(cmp, BLOCKSIZE) <= 0)
        return NULL;

    while (true) {
        need = BLOCKSIZE;
        if (BN_cmp(size, cmp) < 0)
            need = BN_get_word(size);
        if (need == 0)
            break;

        if (BN_sub_word(size, need) <= 0)
            return NULL;

        if (have + (size_t) need >= blocks * BLOCKSIZE) {
            uint8_t *tmp;

            blocks = (have + need + BLOCKSIZE - 1) / BLOCKSIZE;
            tmp = OPENSSL_realloc(buf, blocks * BLOCKSIZE);
            if (tmp == NULL)
                return NULL;

            buf = tmp;
        }

        while (need > 0) {
            rd = BIO_read(in, buf + have, need);
            if (rd <= 0)
                return NULL;

            have += rd;
            need -= rd;
        }
    }

    return ASN1_item_d2i(x, &(const uint8_t *) { buf }, have, it);
}

void *
d2i_fp_max(const ASN1_ITEM *it, FILE *fp, void *x, unsigned int max)
{
    AUTO(BIO, bio);

    bio = BIO_new_fp(fp, BIO_NOCLOSE);
    if (bio == NULL)
        return NULL;

    return d2i_bio_max(it, bio, x, max);
}
