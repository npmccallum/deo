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

#include "asn1.h"

ASN1_SEQUENCE(PETERA_KEY) = {
    ASN1_SIMPLE(PETERA_KEY, hash, ASN1_OCTET_STRING),
    ASN1_SIMPLE(PETERA_KEY, key, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(PETERA_KEY)

ASN1_SEQUENCE(PETERA_MSG_DEC_REQ) = {
    ASN1_SIMPLE(PETERA_MSG_DEC_REQ, cipher, ASN1_OBJECT),
    ASN1_SIMPLE(PETERA_MSG_DEC_REQ, digest, ASN1_OBJECT),

    ASN1_SEQUENCE_OF(PETERA_MSG_DEC_REQ, keys, PETERA_KEY),
    ASN1_SIMPLE(PETERA_MSG_DEC_REQ, data, ASN1_OCTET_STRING),
    ASN1_SIMPLE(PETERA_MSG_DEC_REQ, tag, ASN1_OCTET_STRING),
    ASN1_SIMPLE(PETERA_MSG_DEC_REQ, iv, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(PETERA_MSG_DEC_REQ)

ASN1_CHOICE(PETERA_MSG) = {
    ASN1_EXP(PETERA_MSG, value.err, ASN1_ENUMERATED, PETERA_MSG_TYPE_ERR),
    ASN1_EXP(PETERA_MSG, value.crt_req, ASN1_NULL, PETERA_MSG_TYPE_CRT_REQ),
    ASN1_EXP_SEQUENCE_OF(PETERA_MSG, value.crt_rep, X509, PETERA_MSG_TYPE_CRT_REP),
    ASN1_EXP(PETERA_MSG, value.dec_req, PETERA_MSG_DEC_REQ, PETERA_MSG_TYPE_DEC_REQ),
    ASN1_EXP(PETERA_MSG, value.dec_rep, ASN1_OCTET_STRING, PETERA_MSG_TYPE_DEC_REP),
} ASN1_CHOICE_END(PETERA_MSG)

ASN1_SEQUENCE(PETERA_HEADER) = {
    ASN1_SEQUENCE_OF(PETERA_HEADER, targets, ASN1_UTF8STRING),
    ASN1_SIMPLE(PETERA_HEADER, req, PETERA_MSG_DEC_REQ),
    ASN1_SIMPLE(PETERA_HEADER, iv, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(PETERA_HEADER)

IMPLEMENT_ASN1_FUNCTIONS(PETERA_KEY)
IMPLEMENT_ASN1_FUNCTIONS(PETERA_MSG_DEC_REQ)
IMPLEMENT_ASN1_FUNCTIONS(PETERA_MSG)
IMPLEMENT_ASN1_FUNCTIONS(PETERA_HEADER)

const char *
petera_err_string(PETERA_ERR err)
{
    switch (err) {
    case PETERA_ERR_NONE:
        return "";

    case PETERA_ERR_INTERNAL:
        return "internal error";

    case PETERA_ERR_NOSUPPORT_CIPHER:
        return "cipher unsupported";

    case PETERA_ERR_NOSUPPORT_DIGEST:
        return "digest unsupported";

    case PETERA_ERR_NOTFOUND_KEY:
        return "key not found";
    }

    return "";
}
