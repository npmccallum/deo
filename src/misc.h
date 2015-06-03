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

#include "asn1.h"
#include <stdbool.h>

/* Callback signature for deo_getopt(). Return false on an error. */
typedef bool (*deo_parse)(char c, const char *arg, void *misc);

/* Validates the certificate chain using the specified trust anchors.
 * If anchors is NULL or empty, the default system trust store is used. */
bool
deo_validate(const STACK_OF(X509) *anchors, STACK_OF(X509) *chain);

/* Loads all certificates from the file and adds them to certs. */
bool
deo_load(FILE *fp, STACK_OF(X509) *certs);

/* Sends a request to the server and receives the response. */
DEO_MSG *
deo_request(const STACK_OF(X509) *anchors, const ASN1_UTF8STRING *target,
               const DEO_MSG *req);

/* Callback function for deo_getopt() for parsing anchor arguments. */
bool
deo_anchors(char c, const char *arg, STACK_OF(X509) **misc);

/* Implement consistent getopt style parsing.
 *
 * This function works like getopt(), and even uses getopt() internally.
 * A few differences are worth noting.
 *
 * First, options specified in both opt and keep are processed. However,
 * the options listed in keep are moved to the end of the argv array after
 * optind.
 *
 * Second, option processing is done via callbacks. This is done similar to
 * printf. Each option specified (in either opt or keep) requires two
 * variable arguments. The first is a pointer to a callback function with the
 * signature of deo_parse. The second is a misc value to pass to the
 * callback. If the first variable argument for an option is NULL, no
 * callback will be called. In this case, if the option specified is provided
 * the function will return false;
 */
bool
deo_getopt(int argc, char **argv, const char *opt, const char *keep, ...);

/* Runs a command with the specified stdin and stdout. Returns errno. */
int
deo_run(char *argv[], int in, int out);

/* Exactly like pipe(), just a different signature. */
int
deo_pipe(int *rend, int *wend);

/* Returns true if the passed dirent is a regular file. */
bool
deo_isreg(const char *dir, struct dirent *de);
