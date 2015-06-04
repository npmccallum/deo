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
#include "askp.h"
#include "question.h"
#include "../../cleanup.h"
#include "../../misc.h"

#include <sys/inotify.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define ASK_DIR "/run/systemd/ask-password"

struct askp {
    struct list list;
    int sock;
    int ifd;
    int wfd;
};

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
        struct question *q;

        if (strncmp("ask.", de->d_name, 4) != 0)
            continue;

        q = question_new(ASK_DIR, de->d_name);
        if (q != NULL)
            list_add_after(&(*ctx)->list, &q->list);
    }

    fd->events = POLLIN | POLLPRI;
    fd->fd = (*ctx)->ifd;
    return 0;

error:
    ret = errno;
    askp_free(*ctx);
    return ret;
}

bool
askp_question(struct askp *ctx, struct pollfd *fd)
{
    uint8_t buf[8192] align_as(struct inotify_event);
    struct question *q = NULL;
    bool havenew = false;
    ssize_t len;

    if ((fd->revents & fd->events) == 0)
        return false;
    fd->revents = 0;

    while ((len = read(fd->fd, buf, sizeof(buf))) < 0) {
        if (errno != EAGAIN)
            return false;
    }

    for_event(e, buf, len) {
        if (strncmp("ask.", e->name, 4) != 0)
            continue;

        if (e->mask & IN_MOVED_TO) {
            q = question_new(ASK_DIR, e->name);
            if (q != NULL) {
                list_add_after(&ctx->list, &q->list);
                havenew = true;
            }
            continue;
        }

        LIST_FOREACH(&ctx->list, struct question, q, list) {
            if (strcmp(q->name, e->name) == 0) {
                list_pop(&q->list);
                free(q);
                break;
            }
        }
    }

    return havenew;
}

void
askp_process(struct askp *ctx, char *argv[], const char *keysdir)
{
    char hex[4096] = { '+' };
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return;

    LIST_FOREACH(&ctx->list, struct question, q, list) {
        char path[strlen(keysdir) + strlen(q->uuid) + 2];
        AUTO_FD(rfile);
        AUTO_FD(rpipe);

        strcpy(path, keysdir);
        strcat(path, "/");
        strcat(path, q->uuid);

        if (q->time.tv_sec != 0 || q->time.tv_nsec != 0) {
            if (q->time.tv_sec < now.tv_sec)
                continue;

            if (q->time.tv_sec == now.tv_sec &&
                q->time.tv_nsec < now.tv_nsec)
                continue;
        }

        rfile = open(path, O_RDONLY);
        if (rfile < 0) {
            fprintf(stderr, "Unable to open keyfile (%s): %s\n",
                    path, strerror(errno));
            continue;
        } else {
            AUTO_FD(wpipe);
            int err;

            err = deo_pipe(&rpipe, &wpipe);
            if (err != 0) {
                fprintf(stderr, "Error making pipe: %s\n", strerror(err));
                continue;
            }

            /* NOTE: this code depends on the kernel's pipe buffer being
             * larger than size. This should always be the case with these
             * short keys. */
            err = deo_run(argv, rfile, wpipe);
            if (err != 0) {
                fprintf(stderr, "%s decryption error: %s\n",
                        q->uuid, strerror(err));
                continue;
            } else {
                fprintf(stderr, "%s decryption success\n", q->uuid);
            }
        }

        for (ssize_t r; (r = read(rpipe, hex + strlen(hex),
                                  sizeof(hex) - strlen(hex) - 1)) != 0; ) {
            if (r < 0) {
                fprintf(stderr, "%s read error: %s\n",
                        q->uuid, strerror(errno));
                break;
            }
        }

        sendto(ctx->sock, hex, strlen(hex), 0, &q->sock, sizeof(q->sock));
    }
}

bool
askp_more(struct askp *ctx)
{
    return !LIST_EMPTY(&ctx->list);
}

void
askp_free(struct askp *ctx)
{
    if (!ctx)
        return;

    LIST_FOREACH(&ctx->list, struct question, q, list)
        free(q);

    if (ctx->sock > 0)
        close(ctx->sock);

    if (ctx->wfd > 0)
        close(ctx->wfd);

    if (ctx->ifd > 0)
        close(ctx->ifd);

    free(ctx);
}
