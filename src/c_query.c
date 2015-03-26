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

#include "c_common.h"
#include "cleanup_openssl.h"
#include "common.h"

#include <openssl/err.h>

#include <stdbool.h>
#include <errno.h>

int
cmd_query(int argc, const char **argv)
{
    AUTO_STACK(X509, certs);
    AUTO(SSL_CTX, ctx);

    if (argc != 2)
        return EINVAL;

    ctx = make_ssl_ctx(argv[0]);
    if (ctx == NULL)
        return 1;

    certs = fetch_chain(ctx, argv[1]);
    if (certs == NULL) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    for (int i = 0; i < sk_X509_num(certs); i++)
        PEM_write_X509(stdout, sk_X509_value(certs, i));

    return 0;
}
