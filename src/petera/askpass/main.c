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
#include "iface.h"
#include "list.h"
#include "main.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <error.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

static void
on_signal(int sig)
{
}

int
cmd_askpass(int argc, const char *argv[])
{
    struct iface *iface = NULL;
    struct askp *askp = NULL;
    struct pollfd fds[2];
    struct stat st;
    int ret = EXIT_FAILURE;
    LIST(keys);

    if (argc != 3)
        return EINVAL;

    if (access(argv[0], X_OK) != 0)
        error(EXIT_FAILURE, errno, "Unable to execute binary");

    if (access(argv[2], R_OK) != 0
        || stat(argv[2], &st) != 0
        || !S_ISDIR(st.st_mode))
        error(EXIT_FAILURE, errno, "Unable to access key directory");

    if (iface_new(&iface, &fds[0]) != 0)
        goto error;

    if (askp_new(&askp, &fds[1]) != 0)
        goto error;

    signal(SIGINT, on_signal);
    signal(SIGQUIT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGUSR1, on_signal);
    signal(SIGUSR2, on_signal);

    while (poll(fds, sizeof(fds) / sizeof(*fds), -1) > 0) {
        for (size_t i = 0; i < sizeof(fds) / sizeof(*fds); i++) {
            if (fds[i].revents & (POLLRDHUP | POLLERR | POLLHUP | POLLNVAL))
                goto error;
        }

        if (fds[0].revents & fds[0].events) {
            if (iface_event(iface, argv[0], argv[2], &keys) != 0)
                goto error;
        }
        fds[0].revents = 0;

        if (fds[1].revents & fds[1].events) {
            if (askp_event(askp) != 0)
                goto error;
        }
        fds[1].revents = 0;

        askp_process(askp, &keys);
    }

    if (errno == EINTR)
        ret = EXIT_SUCCESS;

error:
    LIST_FOREACH(&keys, struct key, key, list)
        free(key);

    iface_free(iface);
    askp_free(askp);
    return ret;
}
