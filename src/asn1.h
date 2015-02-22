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

#pragma once

#include <openssl/asn1t.h>
#include <openssl/x509.h>

typedef struct {
    ASN1_OCTET_STRING *confounder;
    ASN1_OCTET_STRING *plaintext;
} PETERA_PLAINTEXT;

typedef struct {
    ASN1_OBJECT *cipher;
    ASN1_OBJECT *digest;
} PETERA_PARAMETERS;

typedef struct {
    ASN1_OCTET_STRING *hash;
    ASN1_OCTET_STRING *key;
} PETERA_KEY;

/* NOTE: We don't currently MAC anything. */
typedef struct {
    STACK_OF(PETERA_KEY) *keys;
    ASN1_OCTET_STRING *data;
    ASN1_OCTET_STRING *iv;
} PETERA_CIPHERTEXT;

typedef struct {
    PETERA_PARAMETERS *parameters;
    PETERA_CIPHERTEXT *ciphertext;
} PETERA_MSG_DEC_REQ;

typedef enum {
    PETERA_ERR_NONE = 0,
    PETERA_ERR_INTERNAL,
    PETERA_ERR_NOSUPPORT_DIGEST,
    PETERA_ERR_NOSUPPORT_CIPHER,
    PETERA_ERR_NOTFOUND_KEY,
} PETERA_ERR;

typedef enum {
    PETERA_MSG_TYPE_ERR = 0,
    PETERA_MSG_TYPE_CRT_REQ,
    PETERA_MSG_TYPE_CRT_REP,
    PETERA_MSG_TYPE_DEC_REQ,
    PETERA_MSG_TYPE_DEC_REP,
} PETERA_MSG_TYPE;

typedef struct {
    PETERA_MSG_TYPE type;
    union {
        ASN1_ENUMERATED *err;
        ASN1_NULL *crt_req;
        STACK_OF(X509) *crt_rep;
        PETERA_MSG_DEC_REQ *dec_req;
        ASN1_OCTET_STRING *dec_rep;
    } value;
} PETERA_MSG;

DECLARE_ASN1_FUNCTIONS(PETERA_PLAINTEXT)
DECLARE_ASN1_FUNCTIONS(PETERA_PARAMETERS)
DECLARE_ASN1_FUNCTIONS(PETERA_KEY)
DECLARE_ASN1_FUNCTIONS(PETERA_CIPHERTEXT)
DECLARE_ASN1_FUNCTIONS(PETERA_MSG_DEC_REQ)
DECLARE_ASN1_FUNCTIONS(PETERA_MSG)

#define SEND_ERR(bio, err) \
    ASN1_item_i2d_bio(&PETERA_MSG_it, bio, &(PETERA_MSG) { \
        .type = PETERA_MSG_TYPE_ERR, \
        .value.err = &(ASN1_ENUMERATED) { \
            .data = &(uint8_t) { err }, \
            .type = V_ASN1_ENUMERATED, \
            .length = 1, \
        } \
    })

const char *
petera_err_string(PETERA_ERR err);
