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
#include "../main.h"
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

static bool
option(char c, const char *arg, const char **misc)
{
    *misc = arg;
    return true;
}

static int
askpass(int argc, char *argv[])
{
    const char *keydir = PETERA_CONF "/disks.d";
    struct iface *iface = NULL;
    AUTO_STACK(X509, anchors);
    struct askp *askp = NULL;
    int ret = EXIT_FAILURE;
    char *dargs[argc + 1];
    struct pollfd fds[2];
    struct stat st;
    LIST(keys);

    if (!petera_getopt(argc, argv, "hk:", "a:", NULL, NULL,
                       option, &keydir, petera_anchors, &anchors)) {
        fprintf(stderr,
                "Usage: petera askpassd "
                "[-k <keydir>] [-a <anchors>] "
                "[<target> ...]\n");
        return EXIT_FAILURE;
    }

    memset(dargs, 0, sizeof(dargs));
    dargs[0] = argv[0];
    dargs[1] = "decrypt";
    memcpy(&dargs[2], &argv[optind], (argc - optind) * sizeof(char *));

    if (access(argv[0], X_OK) != 0)
        error(EXIT_FAILURE, errno, "Unable to execute binary");

    if (access(keydir, R_OK) != 0
        || stat(keydir, &st) != 0
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

    while (poll(fds, sizeof(fds) / sizeof(*fds), 30000) > 0) {
        for (size_t i = 0; i < sizeof(fds) / sizeof(*fds); i++) {
            if (fds[i].revents & (POLLRDHUP | POLLERR | POLLHUP | POLLNVAL))
                goto error;
        }

        if (fds[0].revents & fds[0].events) {
            if (iface_event(iface, dargs, keydir, &keys) != 0)
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

    if (errno == EINTR || errno == 0)
        ret = EXIT_SUCCESS;

error:
    LIST_FOREACH(&keys, struct key, key, list)
        free(key);

    iface_free(iface);
    askp_free(askp);
    return ret;
}

petera_plugin petera = { askpass, NULL };
