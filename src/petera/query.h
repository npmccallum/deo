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

#include "../asn1.h"
#include <stdbool.h>

/* Loads all certificates from the file and adds them to certs.
 * If anchors != NULL, validation is performed.
 * If anchors is empty, the default system anchors are used. */
bool
load(const STACK_OF(X509) *anchors, FILE *fp, STACK_OF(X509) *certs);

/* Sends a request to the server and receives the response.
 * Validation is always performed. If anchors == NULL, the call fails.
 * If anchors is empty, the default system anchors are used. */
PETERA_MSG *
request(const STACK_OF(X509) *anchors, const ASN1_UTF8STRING *target,
        const PETERA_MSG *req);

/* Resolves a target name to a certificate chain.
 * Trust semantics follow request() above. */
bool
query(const STACK_OF(X509) *anchors, const char *target,
      STACK_OF(X509) *certs);
