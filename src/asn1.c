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

ASN1_SEQUENCE(DEO_KEY) = {
    ASN1_SIMPLE(DEO_KEY, hash, ASN1_OCTET_STRING),
    ASN1_SIMPLE(DEO_KEY, key, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(DEO_KEY)

ASN1_SEQUENCE(DEO_MSG_DEC_REQ) = {
    ASN1_SIMPLE(DEO_MSG_DEC_REQ, cipher, ASN1_OBJECT),
    ASN1_SIMPLE(DEO_MSG_DEC_REQ, digest, ASN1_OBJECT),

    ASN1_SEQUENCE_OF(DEO_MSG_DEC_REQ, keys, DEO_KEY),
    ASN1_SIMPLE(DEO_MSG_DEC_REQ, data, ASN1_OCTET_STRING),
    ASN1_SIMPLE(DEO_MSG_DEC_REQ, tag, ASN1_OCTET_STRING),
    ASN1_SIMPLE(DEO_MSG_DEC_REQ, iv, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(DEO_MSG_DEC_REQ)

ASN1_CHOICE(DEO_MSG) = {
    ASN1_EXP(DEO_MSG, value.err, ASN1_ENUMERATED, DEO_MSG_TYPE_ERR),
    ASN1_EXP(DEO_MSG, value.crt_req, ASN1_NULL, DEO_MSG_TYPE_CRT_REQ),
    ASN1_EXP_SEQUENCE_OF(DEO_MSG, value.crt_rep, X509, DEO_MSG_TYPE_CRT_REP),
    ASN1_EXP(DEO_MSG, value.dec_req, DEO_MSG_DEC_REQ, DEO_MSG_TYPE_DEC_REQ),
    ASN1_EXP(DEO_MSG, value.dec_rep, ASN1_OCTET_STRING, DEO_MSG_TYPE_DEC_REP),
} ASN1_CHOICE_END(DEO_MSG)

ASN1_SEQUENCE(DEO_HEADER) = {
    ASN1_SEQUENCE_OF(DEO_HEADER, targets, ASN1_UTF8STRING),
    ASN1_SEQUENCE_OF(DEO_HEADER, anchors, X509),
    ASN1_SIMPLE(DEO_HEADER, req, DEO_MSG_DEC_REQ),
    ASN1_SIMPLE(DEO_HEADER, iv, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(DEO_HEADER)

IMPLEMENT_ASN1_FUNCTIONS(DEO_KEY)
IMPLEMENT_ASN1_FUNCTIONS(DEO_MSG_DEC_REQ)
IMPLEMENT_ASN1_FUNCTIONS(DEO_MSG)
IMPLEMENT_ASN1_FUNCTIONS(DEO_HEADER)

DEFINE_CLEANUP(DEO_KEY)
DEFINE_CLEANUP(DEO_MSG_DEC_REQ)
DEFINE_CLEANUP(DEO_MSG)
DEFINE_CLEANUP(DEO_HEADER)

const char *
deo_err_string(DEO_ERR err)
{
    switch (err) {
    case DEO_ERR_NONE:
        return "";

    case DEO_ERR_INTERNAL:
        return "internal error";

    case DEO_ERR_NOSUPPORT_CIPHER:
        return "cipher unsupported";

    case DEO_ERR_NOSUPPORT_DIGEST:
        return "digest unsupported";

    case DEO_ERR_NOTFOUND_KEY:
        return "key not found";
    }

    return "";
}
