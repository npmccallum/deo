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

#include "cleanup.h"

#include <openssl/asn1t.h>
#include <openssl/x509.h>

typedef struct {
    ASN1_OCTET_STRING *hash;
    ASN1_OCTET_STRING *key;
} DEO_KEY;

typedef struct {
    ASN1_OBJECT *cipher;
    ASN1_OBJECT *digest;

    STACK_OF(DEO_KEY) *keys;
    ASN1_OCTET_STRING *data;
    ASN1_OCTET_STRING *tag;
    ASN1_OCTET_STRING *iv;
} DEO_MSG_DEC_REQ;

typedef enum {
    DEO_ERR_NONE = 0,
    DEO_ERR_INTERNAL,
    DEO_ERR_NOSUPPORT_DIGEST,
    DEO_ERR_NOSUPPORT_CIPHER,
    DEO_ERR_NOTFOUND_KEY,
} DEO_ERR;

typedef enum {
    DEO_MSG_TYPE_ERR = 0,
    DEO_MSG_TYPE_CRT_REQ,
    DEO_MSG_TYPE_CRT_REP,
    DEO_MSG_TYPE_DEC_REQ,
    DEO_MSG_TYPE_DEC_REP,
} DEO_MSG_TYPE;

typedef struct {
    DEO_MSG_TYPE type;
    union {
        ASN1_ENUMERATED *err;
        ASN1_NULL *crt_req;
        STACK_OF(X509) *crt_rep;
        DEO_MSG_DEC_REQ *dec_req;
        ASN1_OCTET_STRING *dec_rep;
    } value;
} DEO_MSG;

typedef struct {
    STACK_OF(ASN1_UTF8STRING) *targets;
    STACK_OF(X509) *anchors;
    DEO_MSG_DEC_REQ *req;
    ASN1_OCTET_STRING *iv;
} DEO_HEADER;

DECLARE_ASN1_FUNCTIONS(DEO_KEY)
DECLARE_ASN1_FUNCTIONS(DEO_MSG_DEC_REQ)
DECLARE_ASN1_FUNCTIONS(DEO_MSG)
DECLARE_ASN1_FUNCTIONS(DEO_HEADER)

DECLARE_CLEANUP(DEO_KEY);
DECLARE_CLEANUP(DEO_MSG_DEC_REQ);
DECLARE_CLEANUP(DEO_MSG);
DECLARE_CLEANUP(DEO_HEADER);

#define SEND_ERR(bio, err) \
    ASN1_item_i2d_bio(&DEO_MSG_it, bio, &(DEO_MSG) { \
        .type = DEO_MSG_TYPE_ERR, \
        .value.err = &(ASN1_ENUMERATED) { \
            .data = &(uint8_t) { err }, \
            .type = V_ASN1_ENUMERATED, \
            .length = 1, \
        } \
    })

const char *
deo_err_string(DEO_ERR err);
