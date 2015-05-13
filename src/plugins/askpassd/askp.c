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
#include "../../cleanup.h"
#include "askp.h"
#include "list.h"
#include "main.h"

#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define UUID_DIR "/dev/disk/by-uuid"
#define ASK_DIR "/run/systemd/ask-password"
#define SECTION "[Ask]\n"
#define PREFIX_ID "\nId=cryptsetup:"
#define PREFIX_SOCKET "\nSocket="
#define PREFIX_NOTAFTER "\nNotAfter="

struct askp {
    struct list list;
    int sock;
    int ifd;
    int wfd;
};

struct item {
    struct list list;
    char *name;
    char *uuid;
    char *sock;
    struct timespec time;
};

static char *
find_uuid_for_dev(const char *dev)
{
    char dpath[PATH_MAX];
    AUTO(DIR, dir);

    if (realpath(dev, dpath) == NULL)
        return NULL;

    dir = opendir(UUID_DIR);
    if (dir == NULL)
        return NULL;

    for (struct dirent *de = readdir(dir); de; de = readdir(dir)) {
        char rpath[PATH_MAX];
        char path[PATH_MAX];

        if (de->d_type != DT_LNK)
            continue;

        if (snprintf(path, sizeof(path), "%s/%s", UUID_DIR, de->d_name) < 0)
            continue;

        if (!realpath(path, rpath))
            continue;

        if (strcmp(rpath, dpath) != 0)
            continue;

        return strdup(de->d_name);
    }

    return NULL;
}

static void
item_free(struct item *a)
{
    if (a == NULL)
        return;

    free(a->uuid);
    free(a->sock);
    free(a->name);
    free(a);
}

static char *
find_prefix_in_section(const char *start, const char *end, const char *prefix)
{
    char *startl = NULL;
    char *endl = NULL;
    size_t plen;

    if (start == NULL || end == NULL || prefix == NULL)
        return NULL;

    plen = strlen(prefix);

    startl = memmem(start, end - start, prefix, plen);
    if (startl == NULL)
        return NULL;
    startl += plen;

    endl = memchr(startl, '\n', end - startl);
    if (endl == NULL)
        return NULL;

    return strndup(startl, endl - startl);
}

static struct item *
item_new(const char *name)
{
    struct item *item = NULL;
    struct stat st = {};
    char path[PATH_MAX];
    char *start = NULL;
    char *file = NULL;
    char *end = NULL;
    char *dev = NULL;
    char *na = NULL;
    AUTO_FD(fd);

    if (snprintf(path, sizeof(path), "%s/%s", ASK_DIR, name) < 0)
        return NULL;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;

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

    item = calloc(1, sizeof(struct item));
    if (!item)
        goto error;

    item->name = strdup(name);
    if (!item->name)
        goto error;

    dev = find_prefix_in_section(start, end, PREFIX_ID);
    if (!dev)
        goto error;

    item->uuid = find_uuid_for_dev(dev);
    free(dev);
    if (!item->uuid)
        goto error;

    na = find_prefix_in_section(start, end, PREFIX_NOTAFTER);
    if (na) {
        long long usec;

        errno = 0;
        usec = strtoll(na, NULL, 10);
        if (errno != 0)
            goto error;

        item->time.tv_sec = usec / 1000000;
        item->time.tv_nsec = usec % 1000000 * 1000;
    } else {
        item->time.tv_sec = (time_t) -1;
        item->time.tv_nsec = -1;
    }

    item->sock = find_prefix_in_section(start, end, PREFIX_SOCKET);
    if (!item->sock)
        goto error;

    munmap(file, st.st_size);
    return item;

error:
    if (file)
        munmap(file, st.st_size);

    item_free(item);
    return NULL;
}

static struct inotify_event *
for_event(struct inotify_event *e, uint8_t *buf, size_t len)
#define for_event(n, b, l) \
    for (struct inotify_event *n = NULL; (n = for_event(n, b, l)); )
{
    uint8_t *tmp;

    if (e == NULL)
        return (struct inotify_event *) buf;

    tmp = (uint8_t *) e + sizeof(struct inotify_event) + e->len;
    if (tmp < buf + len)
        return (struct inotify_event *) tmp;

    return NULL;
}

int
askp_new(struct askp **ctx, struct pollfd *fd)
{
    AUTO(DIR, dir);
    int ret;

    *ctx = calloc(1, sizeof(struct askp));
    if (!*ctx)
        return ENOMEM;

    (*ctx)->list = LIST_INIT((*ctx)->list);

    (*ctx)->sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if ((*ctx)->sock < 0)
        goto error;

    (*ctx)->ifd = inotify_init();
    if ((*ctx)->ifd < 0)
        goto error;

    (*ctx)->wfd = inotify_add_watch((*ctx)->ifd, ASK_DIR,
                                    IN_CLOSE_WRITE | IN_MOVED_TO);
    if ((*ctx)->wfd < 0)
        goto error;

    dir = opendir(ASK_DIR);
    if (dir == NULL)
        goto error;

    for (struct dirent *de = readdir(dir); de; de = readdir(dir)) {
        struct item *item;

        if (strncmp("ask.", de->d_name, 4) != 0)
            continue;

        item = item_new(de->d_name);
        if (item != NULL)
            list_add_after(&(*ctx)->list, &item->list);
    }

    fd->events = POLLIN | POLLPRI | POLLRDHUP;
    fd->fd = (*ctx)->ifd;
    return 0;

error:
    ret = errno;
    askp_free(*ctx);
    return ret;
}

int
askp_event(struct askp *ctx)
{
    uint8_t buf[8192] align_as(struct inotify_event);
    struct item *item;
    ssize_t len;

    while ((len = read(ctx->ifd, buf, sizeof(buf))) < 0) {
        if (errno != EAGAIN)
            return errno;
    }

    for_event(e, buf, len) {
        if (strncmp("ask.", e->name, 4) != 0)
            continue;

        if (e->mask & IN_MOVED_TO) {
            item = item_new(e->name);
            if (item) {
                list_add_after(&ctx->list, &item->list);
            }

            continue;
        }

        LIST_FOREACH(&ctx->list, struct item, item, list) {
            if (strcmp(item->name, e->name) == 0) {
                list_pop(&item->list);
                item_free(item);
                break;
            }
        }
    }

    return 0;
}

void
askp_process(struct askp *ctx, struct list *keys)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return;

    LIST_FOREACH(&ctx->list, struct item, item, list) {
        struct sockaddr_un addr = { AF_UNIX };
        struct key *key = NULL;

        if (item->time.tv_sec != (time_t) -1) {
            if (item->time.tv_sec < now.tv_sec)
                continue;

            if (item->time.tv_sec == now.tv_sec &&
                item->time.tv_nsec < now.tv_nsec)
                continue;
        }

        LIST_FOREACH(keys, struct key, k, list) {
            if (strcmp(k->uuid, item->uuid) == 0) {
                key = k;
                break;
            }
        }
        if (!key)
            continue;

        char buf[key->len * 2 + 2];

        buf[0] = '+';
        for (ssize_t i = 0; i < key->len; i++)
            snprintf(&buf[i * 2 + 1], 3, "%02X", key->key[i]);

        strcpy(addr.sun_path, item->sock);
        sendto(ctx->sock, buf, sizeof(buf), 0, &addr, sizeof(addr));
    }
}

void
askp_free(struct askp *ctx)
{
    if (!ctx)
        return;

    LIST_FOREACH(&ctx->list, struct item, item, list)
        item_free(item);

    if (ctx->sock > 0)
        close(ctx->sock);

    if (ctx->wfd > 0)
        close(ctx->wfd);

    if (ctx->ifd > 0)
        close(ctx->ifd);

    free(ctx);
}
