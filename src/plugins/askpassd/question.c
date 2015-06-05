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

#define _GNU_SOURCE
#include "question.h"
#include "../../cleanup.h"

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

#define UUID_DIR "/dev/disk/by-uuid"
#define SECTION "[Ask]\n"
#define PREFIX_ID "\nId=cryptsetup:"
#define PREFIX_SOCKET "\nSocket="
#define PREFIX_NOTAFTER "\nNotAfter="

static int
find_prefix_in_section(const char *start, const char *end, const char *prefix,
                       char *out, size_t outlen)
{
    char *startl = NULL;
    char *endl = NULL;
    ssize_t plen;

    if (start == NULL || end == NULL || prefix == NULL)
        return EINVAL;

    plen = strlen(prefix);

    startl = memmem(start, end - start, prefix, plen);
    if (startl == NULL)
        return ENOENT;
    startl += plen;

    endl = memchr(startl, '\n', end - startl);
    if (endl == NULL)
        return ENOENT;

    if (outlen < endl - startl + 1)
        return E2BIG;

    plen = snprintf(out, endl - startl + 1, "%s", startl);
    if (plen < 0)
        return errno;

    return 0;
}

static int
find_uuid_for_dev(const char *dev, char *out, size_t outlen)
{
    char dpath[PATH_MAX];
    AUTO(DIR, dir);

    if (realpath(dev, dpath) == NULL)
        return errno;

    dir = opendir(UUID_DIR);
    if (dir == NULL)
        return errno;

    for (struct dirent *de = readdir(dir); de; de = readdir(dir)) {
        char path[strlen(UUID_DIR) + strlen(de->d_name) + 2];
        char rpath[PATH_MAX];

        if (de->d_type != DT_LNK)
            continue;

        strcpy(path, UUID_DIR);
        strcat(path, "/");
        strcat(path, de->d_name);

        if (!realpath(path, rpath))
            continue;

        if (strcmp(rpath, dpath) != 0)
            continue;

        if (snprintf(out, outlen, "%s", de->d_name) != strlen(de->d_name))
            return ENAMETOOLONG;

        return 0;
    }

    return ENOENT;
}

struct question *
question_new(const char *dir, const char *name)
{
    struct question *q = NULL;
    struct stat st = {};
    char tmp[PATH_MAX];
    char *start = NULL;
    char *file = NULL;
    char *end = NULL;
    AUTO_FD(fd);
    int err;

    q = calloc(1, sizeof(struct question));
    if (!q)
        goto error;
    q->sock.sun_family = AF_UNIX;

    if (snprintf(q->name, sizeof(q->name), "%s", name) < 0)
        goto error;

    err = snprintf(tmp, sizeof(tmp), "%s/%s", dir, name);
    if (err < 0)
        goto error;

    fd = open(tmp, O_RDONLY);
    if (fd < 0)
        goto error;

    if (fstat(fd, &st) != 0)
        goto error;

    file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (!file)
        goto error;

    start = memmem(file, st.st_size, SECTION, strlen(SECTION));
    if (!start)
        goto error;

    end = memmem(start, st.st_size - (start - file), "\n[", 2);
    if (!end)
        end = file + st.st_size;

    err = find_prefix_in_section(start, end, PREFIX_ID, tmp, sizeof(tmp));
    if (err != 0)
        goto error;

    err = find_uuid_for_dev(tmp, q->uuid, sizeof(q->uuid));
    if (err != 0)
        goto error;

    err = find_prefix_in_section(start, end, PREFIX_NOTAFTER,
                                 tmp, sizeof(tmp));
    if (err != 0) {
        long long usec;

        errno = 0;
        usec = strtoll(tmp, NULL, 10);
        if (errno != 0)
            goto error;

        q->time.tv_sec = usec / 1000000;
        q->time.tv_nsec = usec % 1000000 * 1000;
    }

    err = find_prefix_in_section(start, end, PREFIX_SOCKET,
                                 q->sock.sun_path, sizeof(q->sock.sun_path));
    if (err != 0)
        goto error;

    munmap(file, st.st_size);
    return q;

error:
    if (file)
        munmap(file, st.st_size);

    free(q);
    return NULL;
}
