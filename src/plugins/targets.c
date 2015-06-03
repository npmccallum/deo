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

static int
targets(int argc, char *argv[])
{
    AUTO(DEO_HEADER, hdr);

    if (!deo_getopt(argc, argv, "h", "", NULL, NULL)) {
        fprintf(stderr, "Usage: deo targets < ENCDATA > TARGETS\n");
        return EXIT_FAILURE;
    }

    hdr = d2i_fp_max(&DEO_HEADER_it, stdin, NULL, DEO_MAX_INPUT);
    if (hdr == NULL) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < sk_ASN1_UTF8STRING_num(hdr->targets); i++) {
        ASN1_UTF8STRING *str = sk_ASN1_UTF8STRING_value(hdr->targets, i);
        fprintf(stdout, "%*s\n", str->length, str->data);
    }

    return EXIT_SUCCESS;
}

deo_plugin deo = {
    targets, "Prints the targets for encrypted input"
};
