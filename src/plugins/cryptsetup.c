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

/* Generate a hex key from nbytes of random data.
 * The hex parameter must be at least 2 * nbytes + 1. */
static int
generate_key(size_t nbytes, char *hex)
{
    uint8_t key[nbytes];
    AUTO(FILE, file);

    file = fopen("/dev/urandom", "r");
    if (file == NULL)
        return -errno;

    if (fread(key, 1, nbytes, file) != nbytes)
        return -errno;

    for (size_t i = 0; i < nbytes; i++)
        snprintf(&hex[i * 2], 3, "%02X", key[i]);

    return 0;
}

static int
make_keyfile(crypt_device *cd, const char *keydir, const char *rand,
             char *argv[])
{
    const char *uuid = NULL;
    char keyfile[PATH_MAX];
    ssize_t written;
    AUTO_FD(rpipe);
    AUTO_FD(wfile);
    int err;

    uuid = crypt_get_uuid(cd);
    if (uuid == NULL)
        return -EINVAL;

    written = snprintf(keyfile, sizeof(keyfile), "%s/%s", keydir, uuid);
    if (written < 0 || written == sizeof(keyfile))
        return -ENAMETOOLONG;
    else {
        AUTO_FD(wpipe);

        if (deo_pipe(&rpipe, &wpipe) != 0)
            return -errno;

        /* NOTE: this code depends on the kernel's pipe buffer being larger
         * than size. This should always be the case with these short keys. */
        written = write(wpipe, rand, strlen(rand));
        if (written < 0)
            return -errno;
        if (written != (ssize_t) strlen(rand))
            return -EMSGSIZE;
    }

    wfile = open(keyfile, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (wfile < 0)
        return -errno;

    err = deo_run(argv, rpipe, wfile);
    if (err != 0) {
        unlink(keyfile);
        return -err;
    }

    return 0;
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
    const char *keydir = DEO_CONF "/disks.d";
    const char *device = NULL;
    AUTO_STACK(X509, anchors);
    const char *type = NULL;
    AUTO(crypt_device, cd);
    char *args[argc + 1];
    int keysize = 0;
    int nerr = 0;
    int slot = 0;

    if (!deo_getopt(argc, argv, "hk:d:", "a:", NULL, NULL, option, &keydir,
                       option, &device, deo_anchors, &anchors)
        || device == NULL || sk_X509_num(anchors) == 0 || argc - optind < 1) {
        fprintf(stderr, "Usage: deo cryptsetup "
                        "[-k <keydir>] -d <device> "
                        "-a <anchors> <target> [...]\n");
        return EXIT_FAILURE;
    }

    memset(args, 0, sizeof(args));
    args[0] = argv[0];
    args[1] = "encrypt";
    memcpy(&args[2], &argv[optind], (argc - optind) * sizeof(char *));

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

    char hex[keysize * 2 + 1];

    nerr = generate_key(keysize, hex);
    if (nerr != 0)
        error(1, -nerr, "Unable to generate key");

    slot = crypt_keyslot_add_by_passphrase(cd, CRYPT_ANY_SLOT, NULL, 0,
                                           hex, sizeof(hex) - 1);
    if (slot < 0)
        error(1, -slot, "Unable to add passphrase");

    nerr = make_keyfile(cd, keydir, hex, args);
    if (nerr != 0) {
        crypt_keyslot_destroy(cd, slot);
        error(1, -nerr, "Unable to make keyfile");
    }

    return 0;
}

deo_plugin deo = {
    cryptsetup, "Enable deo on a LUKS partition"
};
