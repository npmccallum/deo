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
#include "iface.h"
#include "list.h"
#include "main.h"
#include "../../cleanup.h"
#include "../../misc.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

struct item {
    struct list list;
    struct {
        sa_family_t family;
        char iface[IF_NAMESIZE];
        union {
            struct in_addr ipv4;
            struct in6_addr ipv6;
        } addr;
    } addr;
    bool isnew;
};

struct iface {
    struct list list;
    int fd;
};

static int
request_existing(int sock, int family)
{
    struct {
        struct nlmsghdr h;
        struct ifaddrmsg m;
    } req = {
        { NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
          RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 0, getpid() },
        { family }
    };

    return send(sock, &req, sizeof(req), 0);
}

int
iface_new(struct iface **ctx, struct pollfd *fd)
{
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR
    };
    int ret;

    *ctx = calloc(1, sizeof(struct iface));
    if (!*ctx)
        return ENOMEM;

    (*ctx)->list = LIST_INIT((*ctx)->list);
    (*ctx)->fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if ((*ctx)->fd < 0)
        goto error;

    if (bind((*ctx)->fd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
        goto error;

    request_existing((*ctx)->fd, AF_INET);
    request_existing((*ctx)->fd, AF_INET6);

    fd->events = POLLIN | POLLPRI | POLLRDHUP;
    fd->fd = (*ctx)->fd;
    return 0;

error:
    ret = errno;
    iface_free(*ctx);
    return ret;
}

static ssize_t
decrypt(char *argv[], const char *keyfile, ssize_t size, uint8_t *key)
{
    AUTO_FD(rfile);
    AUTO_FD(rpipe);
    ssize_t t = 0;
    int err;

    rfile = open(keyfile, O_RDONLY);
    if (rfile < 0)
        return -errno;
    else {
        AUTO_FD(wpipe);

        if (petera_pipe(&rpipe, &wpipe) != 0)
            return -errno;

        /* NOTE: this code depends on the kernel's pipe buffer being larger
         * than size. This should always be the case with these short keys. */
        err = petera_run(argv, rfile, wpipe);
        if (err != 0)
            return -err;
    }

    for (ssize_t r; (r = read(rpipe, key + t, size - t)) != 0; t += r) {
        if (r < 0)
            return -errno;
    }

    return t;
}


int
iface_event(struct iface *ctx, char *argv[],
            const char *keysdir, struct list *keys)
{
    uint8_t buf[4096] align_as(struct nlmsghdr);
    bool havenew = false;
    AUTO(DIR, dir);
    int len;

    while ((len = read(ctx->fd, buf, sizeof(buf))) < 0) {
        if (errno != EAGAIN)
            return errno;
    }

    for (struct nlmsghdr *msghdr = (struct nlmsghdr *) buf;
         NLMSG_OK(msghdr, len) && msghdr->nlmsg_type != NLMSG_DONE;
         msghdr = NLMSG_NEXT(msghdr, len)) {
        struct ifaddrmsg *addrmsg = (struct ifaddrmsg *) NLMSG_DATA(msghdr);
        int rtlen = IFA_PAYLOAD(msghdr);

        switch (msghdr->nlmsg_type) {
        case RTM_NEWADDR:
        case RTM_DELADDR:
            break;

        default:
            continue;
        }

        for (struct rtattr *attr = IFA_RTA(addrmsg);
             RTA_OK(attr, rtlen);
             attr = RTA_NEXT(attr, rtlen)) {
            struct item addr = { .isnew = true};
            struct item *have = NULL;

            if (attr->rta_type != IFA_LOCAL)
                continue;

            if (if_indextoname(addrmsg->ifa_index, addr.addr.iface) == NULL)
                continue;

            addr.addr.family = addrmsg->ifa_family;
            switch (addr.addr.family) {
            case AF_INET:
                memcpy(&addr.addr.addr.ipv4, RTA_DATA(attr),
                       sizeof(addr.addr.addr.ipv4));
                break;

            case AF_INET6:
                memcpy(&addr.addr.addr.ipv6, RTA_DATA(attr),
                       sizeof(addr.addr.addr.ipv6));
                break;

            default:
                continue;
            }

            LIST_FOREACH(&ctx->list, struct item, item, list) {
                if (memcmp(&item->addr, &addr.addr, sizeof(addr.addr)) == 0) {
                    have = item;
                    break;
                }
            }

            switch (msghdr->nlmsg_type) {
            case RTM_NEWADDR:
                if (have)
                    continue;

                have = malloc(sizeof(*have));
                if (have == NULL)
                    return ENOMEM;

                memcpy(have, &addr, sizeof(addr));
                list_add_after(&ctx->list, &have->list);
                break;

            case RTM_DELADDR:
                if (have)
                    list_pop(&have->list);
                free(have);
                break;
            }
        }
    }

    LIST_FOREACH(&ctx->list, struct item, item, list) {
        havenew |= item->isnew;
        item->isnew = false;
    }
    if (!havenew)
        return 0;

    dir = opendir(keysdir);
    if (dir == NULL)
        return errno;

    for (struct dirent *de = readdir(dir); de; de = readdir(dir)) {
        struct key *key = NULL;
        bool already = false;
        char path[PATH_MAX];

        if (de->d_type != DT_REG)
            continue;

        if (strlen(de->d_name) != UUID_SIZE)
            continue;

        LIST_FOREACH(keys, struct key, k, list) {
            if (strcmp(k->uuid, de->d_name) == 0) {
                already = true;
                break;
            }
        }
        if (already)
            continue;

        if (snprintf(path, sizeof(path), "%s/%s", keysdir, de->d_name) < 0)
            continue;

        key = calloc(1, sizeof(struct key));
        if (key == NULL)
            continue;

        key->len = decrypt(argv, path, sizeof(key->key), key->key);
        if (key->len < 0) {
            fprintf(stderr, "Unable to decrypt key (%s): %s\n",
                    de->d_name, strerror(-key->len));
            free(key);
            continue;
        }

        strncpy(key->uuid, de->d_name, sizeof(key->uuid));
        list_add_after(keys, &key->list);
    }

    return 0;
}

void
iface_free(struct iface *ctx)
{
    if (!ctx)
        return;

    LIST_FOREACH(&ctx->list, struct item, item, list)
        free(item);

    if (ctx->fd > 0)
        close(ctx->fd);

    free(ctx);
}
