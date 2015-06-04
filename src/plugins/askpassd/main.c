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

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <error.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#define TIMEOUT_BASE 5000
#define TIMEOUT_EXT (rand() % 295000)
#define ALLCNT (sizeof(struct all) / sizeof(struct pollfd))

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

struct all {
    struct pollfd askp;
    struct pollfd iface;
};

static int
askpass(int argc, char *argv[])
{
    const char *keydir = DEO_CONF "/disks.d";
    int timeout = TIMEOUT_BASE;
    AUTO_STACK(X509, anchors);
    struct askp *askp = NULL;
    int ret = EXIT_FAILURE;
    char *dargs[argc + 1];
    struct stat st;
    int events;
    LIST(keys);

    union {
        struct pollfd all[ALLCNT];
        struct all ind;
    } fds;

    if (!deo_getopt(argc, argv, "hk:", "a:", NULL, NULL,
                       option, &keydir, deo_anchors, &anchors)) {
        fprintf(stderr,
                "Usage: deo askpassd "
                "[-k <keydir>] [-a <anchors>] "
                "[<target> ...]\n");
        return EXIT_FAILURE;
    }

    memset(dargs, 0, sizeof(dargs));
    dargs[0] = argv[0];
    dargs[1] = "decrypt";
    memcpy(&dargs[2], &argv[optind], (argc - optind) * sizeof(char *));

    if (access(keydir, R_OK) != 0
        || stat(keydir, &st) != 0
        || !S_ISDIR(st.st_mode))
        error(EXIT_FAILURE, errno, "Unable to access key directory");

    if (askp_new(&askp, &fds.ind.askp) != 0)
        goto error;

    if (iface_new(&fds.ind.iface) != 0)
        goto error;

    signal(SIGINT, on_signal);
    signal(SIGQUIT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGUSR1, on_signal);
    signal(SIGUSR2, on_signal);

    for (int i = 0; i < ALLCNT; i++)
        fds.all[i].events |= POLLRDHUP;

    while ((events = poll(fds.all, ALLCNT, timeout)) >= 0) {
        bool process = false;

        for (int i = 0; i < ALLCNT; i++) {
            short mask = ~fds.all[i].events | POLLRDHUP;
            if (fds.all[i].revents & mask)
                goto error;
        }

        if (events == 0) {
            askp_process(askp, dargs, keydir);

            if (!askp_more(askp))
                break;

            timeout = TIMEOUT_BASE + TIMEOUT_EXT;
            continue;
        }

        timeout = TIMEOUT_BASE;
        process |= iface_route(&fds.ind.iface);
        process |= askp_question(askp, &fds.ind.askp);
        if (process)
            askp_process(askp, dargs, keydir);
    }

    if (errno == EINTR || errno == 0)
        ret = EXIT_SUCCESS;

error:
    close(fds.ind.iface.fd);
    close(fds.ind.askp.fd);
    askp_free(askp);
    return ret;
}

deo_plugin deo = { askpass, NULL };
