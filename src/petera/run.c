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

#include "../cleanup.h"
#include "../main.h"
#include "../d2i.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "query.h"
#include "encrypt.h"
#include "decrypt.h"

int
cmd_askpass(int argc, const char **argv);

int
cmd_cryptsetup(int argc, const char *argv[]);

static int
parse_options(int *argc, const char **argv[], STACK_OF(X509) *anchors)
{
    AUTO(FILE, file);

    optind = 2;
    for (int c; (c = getopt(*argc, (char **) *argv, "a:")) != -1; ) {
        switch (c) {
        case 'a':
            file = fopen(optarg, "r");
            if (file == NULL) {
                fprintf(stderr, "Unable to open anchor file (%s)! %s\n",
                        optarg, strerror(errno));
                return EINVAL;
            }

            if (!load(NULL, file, anchors)) {
                fprintf(stderr, "Unable to parse anchor file (%s)!\n",
                        optarg);
                return EINVAL;
            }

            break;

        default:
            return EINVAL;
        }
    }

    *argc -= optind;
    *argv += optind;
    return 0;
}

int
cmd_query(int argc, const char *argv[])
{
    AUTO_STACK(X509, anchors);
    AUTO_STACK(X509, certs);

    anchors = sk_X509_new_null();
    certs = sk_X509_new_null();
    if (anchors == NULL || certs == NULL)
        return EXIT_FAILURE;

    if (parse_options(&argc, &argv, anchors) != 0)
        return EINVAL;

    if (argc != 1)
        return EINVAL;

    if (!query(anchors, argv[0], certs))
        return EXIT_FAILURE;

    for (int i = 0; i < sk_X509_num(certs); i++)
        PEM_write_X509(stdout, sk_X509_value(certs, i));

    return EXIT_SUCCESS;
}

static int
cmd_encrypt(int argc, const char **argv)
{
    AUTO_STACK(X509, anchors);

    anchors = sk_X509_new_null();
    if (anchors == NULL)
        return EXIT_FAILURE;

    if (parse_options(&argc, &argv, anchors) != 0)
        return EINVAL;

    if (argc < 1)
        return EINVAL;

    return encrypt(anchors, argc, argv, stdin, stdout)
            ? EXIT_SUCCESS : EXIT_FAILURE;
}

int
cmd_decrypt(int argc, const char *argv[])
{
    AUTO_STACK(X509, anchors);

    anchors = sk_X509_new_null();
    if (anchors == NULL)
        return EXIT_FAILURE;

    if (parse_options(&argc, &argv, anchors) != 0)
        return EINVAL;

    return decrypt(anchors, argc, argv, stdin, stdout)
                ? EXIT_SUCCESS : EXIT_FAILURE;
}

int
cmd_targets(int argc, const char **argv)
{
    AUTO(PETERA_HEADER, hdr);

    hdr = d2i_fp_max(&PETERA_HEADER_it, stdin, NULL, PETERA_MAX_INPUT);
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

static const struct {
    const char *name;
    const char *doc;
    const char *stdin;
    const char *stdout;
    const char *args;
    int (*cmd)(int argc, const char *argv[]);
} COMMANDS[] = {
    { "query",
      "Fetches and verifies a server's encryption certificate chain",
      "N/A",
      "PEM encoded certificate chain",
      "[-a <anchor(s)> ...] <host[:port]>",
      cmd_query },
    { "encrypt",
      "Encrypts input to all specified targets",
      "Plaintext data to encrypt",
      "Encryption of input data",
      "[-a <anchor(s)> ...] <host[:port]|file> [...]",
      cmd_encrypt },
    { "decrypt",
      "Decrypts input using any of the targets",
      "Ciphertext data to decrypt",
      "Decrypted plaintext",
      "[-a <anchor(s)> ...] [<host[:port]> ...]",
      cmd_decrypt },
    { "targets",
      "Prints the targets for encrypted input",
      "Ciphertext data",
      "List of targets",
      "",
      cmd_targets },
    { "askpass",
      "Daemon which listens on the systemd askpass interface",
      "",
      "",
      "",
      cmd_askpass },
    { "cryptsetup",
      "Enable petera on a LUKS partition",
      "",
      "",
      "<device> <anchor.pem> <target> [...]",
      cmd_cryptsetup },
    {}
};

int
run(int argc, const char **argv)
{
    int ret;

    if (argc >= 2) {
        for (int i = 0; COMMANDS[i].name != NULL; i++) {
            if (strcmp(COMMANDS[i].name, argv[1]) == 0) {
                ret = COMMANDS[i].cmd(argc, argv);
                if (ret == EINVAL)
                    break;
                return ret;
            }
        }
    }

    fprintf(stderr,
            "Usage: %s <COMMAND> [...]\n\n",
            argv[0]);
    fprintf(stderr, "COMMANDS\n");

    for (int i = 0; COMMANDS[i].name != NULL; i++) {
        fprintf(stderr, "%12s  %s.\n", COMMANDS[i].name, COMMANDS[i].doc);
        fprintf(stderr, "%12s  Args: %s\n", "", COMMANDS[i].args);
        fprintf(stderr, "%12s  STDIN:  %s\n", "", COMMANDS[i].stdin);
        fprintf(stderr, "%12s  STDOUT: %s\n", "", COMMANDS[i].stdout);
        fprintf(stderr, "\n");
    }

    return 1;
}
