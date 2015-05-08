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
#include "decrypt.h"
#include "../d2i.h"
#include "../main.h"

#include <openssl/err.h>
#include <systemd/sd-daemon.h>

#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

static bool
have_conn(int lfds, int sock, int *fd)
{
    struct pollfd pfds[lfds > 0 ? lfds : 1];

    if (lfds > 0) {
        for (int i = 0; i < lfds; i++) {
            pfds[i].fd = SD_LISTEN_FDS_START + i;
            pfds[i].events = POLLIN | POLLPRI | POLLOUT;
        }
    } else if (sock >= 0) {
        pfds[0].fd = sock;
        pfds[0].events = POLLIN | POLLPRI | POLLOUT;
    } else
        return false;

    if (poll(pfds, lfds > 0 ? lfds : 1, -1) <= 0)
        return false;

    for (int i = 0; i < (lfds > 0 ? lfds : 1); i++) {
        if ((pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
            return false;
    }

    for (int i = 0; i < (lfds > 0 ? lfds : 1); i++) {
        if (pfds[i].revents != 0) {
            *fd = pfds[i].fd;
            return true;
        }
    }

    return false;
}

static bool
do_accept(SSL_CTX *ctx, int fd, int *client, BIO **sio)
{
    SSL *ssl;

    *client = accept(fd, NULL, NULL);
    if (*client < 0)
        return false;

    *sio = BIO_new_ssl(ctx, 0);
    if (*sio == NULL)
        return false;

    if (BIO_get_ssl(*sio, &ssl) <= 0)
        return false;

    if (SSL_set_fd(ssl, *client) <= 0)
        return false;

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    return true;
}

static void
on_signal(int sig)
{
}

int
run(int argc, char **argv)
{
    char *hp = PETERA_SOCKET;
    int ret = EXIT_FAILURE;
    AUTO(ctx, ctx);
    int lfds = 0;
    int sock = 0;

    signal(SIGINT, on_signal);
    signal(SIGQUIT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGUSR1, on_signal);
    signal(SIGUSR2, on_signal);

    if (argc >= 4) {
        ctx = ctx_init(argv[1], argv[2], argv[3]);
        if (ctx == NULL)
            ERR_print_errors_fp(stderr);

        if (argc >= 5)
            hp = argv[4];
    }

    if (ctx == NULL) {
        fprintf(
            stderr,
            "Usage: %s <tls_file> <enc_chain> <dec_dir> [<[host:]port>]\n",
            argv[0]
        );

        return 1;
    }

    lfds = sd_listen_fds(0);
    if (lfds <= 0) {
        sock = BIO_get_accept_socket(hp, 0);
        if (sock < 0) {
            ERR_print_errors_fp(stderr);
            goto error;
        }

        if (listen(sock, 64) != 0)
            goto error;
    }

    while (true) {
        PETERA_ERR err = PETERA_ERR_NONE;
        AUTO(ASN1_OCTET_STRING, pt);
        AUTO(PETERA_MSG, in);
        AUTO(BIO, sio);
        AUTO_FD(cfd);
        int lfd;

        if (!have_conn(lfds, sock, &lfd))
            break;

        if (!do_accept(ctx->ctx, lfd, &cfd, &sio))
            continue;

        in = d2i_bio_max(&PETERA_MSG_it, sio, NULL, PETERA_MAX_INPUT);
        if (in == NULL)
            continue;

        switch (in->type) {
        case PETERA_MSG_TYPE_CRT_REQ:
            ASN1_item_i2d_bio(&PETERA_MSG_it, sio, &(PETERA_MSG) {
                .type = PETERA_MSG_TYPE_CRT_REP,
                .value.crt_rep = ctx->crt
            });
            break;

        case PETERA_MSG_TYPE_DEC_REQ:
            err = decrypt(ctx, in->value.dec_req, &pt);
            if (err != PETERA_ERR_NONE) {
                SEND_ERR(sio, err);
                break;
            }

            ASN1_item_i2d_bio(&PETERA_MSG_it, sio, &(PETERA_MSG) {
                .type = PETERA_MSG_TYPE_DEC_REP,
                .value.dec_rep = pt
            });
            break;

        default:
            break;
        }
    }

    ret = EXIT_SUCCESS;

error:
    if (ret != EXIT_SUCCESS)
        ERR_print_errors_fp(stderr);
    return ret;
}
