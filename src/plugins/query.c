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

#include <error.h>
#include <unistd.h>

static int
query(int argc, char *argv[])
{
    DEO_ERR err = DEO_ERR_NONE;
    AUTO_STACK(X509, anchors);
    AUTO(DEO_MSG, rep);

    if (!deo_getopt(argc, argv, "ha:", "", NULL, NULL,
                       deo_anchors, &anchors)
        || sk_X509_num(anchors) == 0 || argc - optind != 1) {
        fprintf(stderr, "Usage: deo query -a <anchors> <target>\n");
        return EXIT_FAILURE;
    }

    rep = deo_request(anchors, &(ASN1_UTF8STRING) {
        .data = (uint8_t *) argv[optind],
        .length = strlen(argv[optind])
    }, &(DEO_MSG) {
        .type = DEO_MSG_TYPE_CRT_REQ,
        .value.crt_req = &(ASN1_NULL) {0}
    });

    if (rep == NULL) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    switch (rep->type) {
    case DEO_MSG_TYPE_ERR:
        err = ASN1_ENUMERATED_get(rep->value.err);
        error(EXIT_FAILURE, 0, "Server error: %s", deo_err_string(err));

    case DEO_MSG_TYPE_CRT_REP:
        if (!deo_validate(anchors, rep->value.crt_rep))
            error(EXIT_FAILURE, 0, "Validation failed: %s", argv[optind]);

        for (int i = 0; i < sk_X509_num(rep->value.crt_rep); i++)
            PEM_write_X509(stdout, sk_X509_value(rep->value.crt_rep, i));

        return 0;

    default:
        error(EXIT_FAILURE, 0, "Invalid response");
    }

    return EXIT_FAILURE;
}

deo_plugin deo = {
    query, "Fetches and verifies a server's encryption certificate chain"
};
