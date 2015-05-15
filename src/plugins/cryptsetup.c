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

#include <libcryptsetup.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct crypt_device crypt_device;

static void
cleanup_crypt_device(crypt_device **cd)
{
    if (cd == NULL || *cd == NULL)
        return;

    crypt_free(*cd);
}

static int
generate_key(uint8_t *key, size_t size, char *hexkey)
{
    AUTO(FILE, file);

    file = fopen("/dev/urandom", "r");
    if (file == NULL)
        return -errno;

    if (fread(key, 1, size, file) != size)
        return -errno;

    for (size_t i = 0; i < size; i++)
        snprintf(&hexkey[i * 2], 3, "%02X", key[i]);

    return 0;
}

static int
make_keyfile(crypt_device *cd, const char *keydir, const uint8_t *rand,
             size_t size, char *argv[])
{
    const char *uuid = NULL;
    char keyfile[PATH_MAX];
    ssize_t written;
    int status;
    pid_t pid;
    int in[2];
    int fd;

    uuid = crypt_get_uuid(cd);
    if (uuid == NULL)
        return -EINVAL;

    status = snprintf(keyfile, sizeof(keyfile), "%s/%s", keydir, uuid);
    if (status < 0 || status == sizeof(keyfile))
        return -ENAMETOOLONG;

    fd = open(keyfile, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd < 0)
        return -errno;

    if (pipe(in) != 0)
        return -errno;

    pid = fork();
    if (pid < 0) {
        close(in[0]);
        close(in[1]);
        return -errno;
    } else if (pid == 0) {
        close(in[1]);

        if (dup2(in[0], STDIN_FILENO) < 0)
            exit(1);

        if (dup2(fd, STDOUT_FILENO) < 0)
            exit(1);

        execvp(argv[0], argv);
        error(EXIT_FAILURE, errno, "Execution error");
    }

    written = write(in[1], rand, size);
    close(in[0]);
    close(in[1]);
    close(fd);

    if (waitpid(pid, &status, 0) != pid)
        return -errno;

    if (WIFEXITED(status)
        && WEXITSTATUS(status) == 0
        && written == (ssize_t) size)
        return 0;

    unlink(keyfile);
    return -EPIPE;
}

static bool
option(char c, const char *arg, const char **misc)
{
    *misc = arg;
    return true;
}

static int
cryptsetup(int argc, char *argv[])
{
    const char *keydir = PETERA_CONF "/disks.d";
    const char *device = NULL;
    AUTO_STACK(X509, anchors);
    const char *type = NULL;
    AUTO(crypt_device, cd);
    char *eargs[argc + 1];
    int keysize = 0;
    int nerr = 0;
    int slot = 0;

    if (!petera_getopt(argc, argv, "hk:d:", "a:", NULL, NULL, option, &keydir,
                       option, &device, petera_anchors, &anchors)
        || device == NULL || sk_X509_num(anchors) == 0 || argc - optind < 1) {
        fprintf(stderr, "Usage: petera cryptsetup "
                        "[-k <keydir>] -d <device> "
                        "-a <anchors> <target> [...]\n");
        return EXIT_FAILURE;
    }

    memset(eargs, 0, sizeof(eargs));
    eargs[0] = argv[0];
    eargs[1] = "encrypt";
    memcpy(&eargs[2], &argv[optind], (argc - optind) * sizeof(char *));

    nerr = crypt_init(&cd, device);
    if (nerr != 0)
        error(1, -nerr, "Unable to open device (%s)", device);

    nerr = crypt_load(cd, NULL, NULL);
    if (nerr != 0)
        error(1, -nerr, "Unable to load device (%s)", device);

    type = crypt_get_type(cd);
    if (type == NULL)
        error(1, 0, "Unable to determine device type");
    if (strcmp(type, CRYPT_LUKS1) != 0)
        error(1, 0, "%s (%s) is not a LUKS device", device, type);

    keysize = crypt_get_volume_key_size(cd);
    if (keysize < 16) /* Less than 128-bits. */
        error(1, 0, "Key size (%d) is too small", keysize);

    uint8_t key[keysize];
    char hexkey[keysize * 2 + 1];

    nerr = generate_key(key, sizeof(key), hexkey);
    if (nerr != 0)
        error(1, -nerr, "Unable to generate key");

    slot = crypt_keyslot_add_by_passphrase(cd, CRYPT_ANY_SLOT, NULL, 0,
                                           hexkey, sizeof(hexkey) - 1);
    if (slot < 0)
        error(1, -slot, "Unable to add passphrase");

    nerr = make_keyfile(cd, keydir, key, sizeof(key), eargs);
    if (nerr != 0) {
        crypt_keyslot_destroy(cd, slot);
        error(1, -nerr, "Unable to make keyfile");
    }

    return 0;
}

petera_plugin petera = {
    cryptsetup, "Enable petera on a LUKS partition"
};
