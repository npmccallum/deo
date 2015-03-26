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

#include "common.h"
#include "asn1.h"
#include "d2i.h"

#include <errno.h>
#include <openssl/err.h>

int
cmd_retarget(int argc, const char **argv)
{
    AUTO(PETERA_HEADER, hdr);
    uint8_t buf[4096];
    size_t len;

    if (argc < 1)
        return EINVAL;

    hdr = d2i_fp_max(&PETERA_HEADER_it, stdin, NULL, PETERA_MAX_INPUT);
    if (hdr == NULL) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    while (sk_ASN1_UTF8STRING_num(hdr->targets) > 0) {
        ASN1_UTF8STRING *str = sk_ASN1_UTF8STRING_pop(hdr->targets);
        ASN1_UTF8STRING_free(str);
    }

    for (int i = 0; i < argc; i++) {
        ASN1_UTF8STRING *target = NULL;

        target = ASN1_UTF8STRING_new();
        if (target == NULL)
            return ENOMEM;

        if (sk_ASN1_UTF8STRING_push(hdr->targets, target) != 1) {
            ASN1_UTF8STRING_free(target);
            return ENOMEM;
        }

        if (ASN1_STRING_set(target, argv[i], strlen(argv[i])) != 1)
            return ENOMEM;
    }

    if (ASN1_item_i2d_fp(&PETERA_HEADER_it, stdout, hdr) != 1)
        return EXIT_FAILURE;

    while (!feof(stdin)) {
        len = fread(buf, 1, sizeof(buf), stdin);
        if (ferror(stdin))
            return EXIT_FAILURE;

        if (fwrite(buf, 1, len, stdout) != (size_t) len)
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
