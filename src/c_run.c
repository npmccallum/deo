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

#include "cleanup.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "c_fetch.h"
#include "c_encrypt.h"
#include "c_decrypt.h"

static const struct {
    const char *name;
    const char *doc;
    const char *stdin;
    const char *stdout;
    const char *args;
    int (*cmd)(SSL_CTX *ctx, int argc, const char **argv);
} COMMANDS[] = {
    { "fetch",
      "Fetches and verifies a server's encryption certificate chain",
      "N/A",
      "PEM encoded certificate chain",
      "<host[:port]>",
      cmd_fetch },
    { "encrypt",
      "Encrypts input to all specified certificates",
      "Plaintext data to encrypt",
      "Encryption of input data",
      "<host[:port]|file> [...]",
      cmd_encrypt },
    { "decrypt",
      "Decrypts input using any of the servers",
      "Ciphertext data to decrypt",
      "Decrypted plaintext",
      "<host[:port]> [...]",
      cmd_decrypt },
    {}
};

int
run(int argc, const char **argv)
{
    AUTO(SSL_CTX, ctx);
    struct stat st;
    int ret;

    if (argc >= 4) {
        ctx = SSL_CTX_new(TLSv1_2_client_method());
        if (ctx == NULL)
            return 1;

        if (lstat(argv[1], &st) != 0) {
            fprintf(stderr, "Anchor: %s\n", strerror(errno));
            return 1;
        }

        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Anchor: invalid file type\n");
            return 1;
        }

        if (S_ISREG(st.st_mode)
            && SSL_CTX_load_verify_locations(ctx, argv[1], NULL) <= 0) {
            ERR_print_errors_fp(stderr);
            return 1;
        }

        if (S_ISDIR(st.st_mode)
            && SSL_CTX_load_verify_locations(ctx, NULL, argv[1]) <= 0) {
            ERR_print_errors_fp(stderr);
            return 1;
        }

        for (int i = 0; COMMANDS[i].name != NULL; i++) {
            if (strcmp(COMMANDS[i].name, argv[2]) == 0) {
                ret = COMMANDS[i].cmd(ctx, argc - 3, &argv[3]);
                if (ret == EINVAL)
                    break;
                return ret;
            }
        }
    }

    fprintf(stderr,
            "Usage: %s <anchor(s)> <COMMAND> [...]\n\n",
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
