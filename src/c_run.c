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

int
cmd_query(int argc, const char **argv);

int
cmd_encrypt(int argc, const char **argv);

int
cmd_decrypt(int argc, const char **argv);

static const struct {
    const char *name;
    const char *doc;
    const char *stdin;
    const char *stdout;
    const char *args;
    int (*cmd)(int argc, const char **argv);
} COMMANDS[] = {
    { "query",
      "Fetches and verifies a server's encryption certificate chain",
      "N/A",
      "PEM encoded certificate chain",
      "<anchor(s)> <host[:port]>",
      cmd_query },
    { "encrypt",
      "Encrypts input to all specified certificates",
      "Plaintext data to encrypt",
      "Encryption of input data",
      "<anchor(s)> <host[:port]|file> [...]",
      cmd_encrypt },
    { "decrypt",
      "Decrypts input using any of the servers",
      "Ciphertext data to decrypt",
      "Decrypted plaintext",
      "<anchor(s)> <host[:port]> [...]",
      cmd_decrypt },
    {}
};

int
run(int argc, const char **argv)
{
    int ret;

    if (argc >= 2) {
        for (int i = 0; COMMANDS[i].name != NULL; i++) {
            if (strcmp(COMMANDS[i].name, argv[1]) == 0) {
                ret = COMMANDS[i].cmd(argc - 2, &argv[2]);
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
