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

#include "main.h"
#include "cleanup.h"
#include "d2i.h"

#include <dlfcn.h>
#include <errno.h>
#include <error.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_PLUGINS 128

struct record {
    void *dll;
    char *name;
    deo_plugin plug;
};

static struct {
    size_t cnt;
    struct record rec[MAX_PLUGINS];
} inv;

static int
cmp(const void *a, const void *b)
{
    const struct record *aa = a;
    const struct record *bb = b;
    return strcmp(aa->name, bb->name);
}

static void
onexit(void)
{
    for (size_t i = 0; i < inv.cnt; i++) {
        dlclose(inv.rec[i].dll);
        free(inv.rec[i].name);
    }

    EVP_cleanup();
}

static bool
endswith(const char *haystack, const char *needle)
{
    size_t hlen;
    size_t nlen;

    if (haystack == NULL || needle == NULL)
        return false;

    hlen = strlen(haystack);
    nlen = strlen(needle);

    if (hlen < nlen)
        return false;

    return strcmp(haystack + hlen - nlen, needle) == 0;
}

#define append(dst, src) strncat(dst, src, sizeof(dst) - strlen(dst) - 1)

static const char *
make_plugin_name(const char *plugindir, const char *name)
{
    static char path[PATH_MAX];

    memset(path, 0, sizeof(path));

    append(path, plugindir);
    append(path, "/");
    append(path, name);
    if (!endswith(path, LT_MODULE_EXT))
        append(path, LT_MODULE_EXT);

    return path;
}

#include <assert.h>

static void
load_plugin(const char *path)
{
    const deo_plugin *tmp = NULL;
    const char *tmpx;

    if (inv.cnt >= MAX_PLUGINS)
        error(EXIT_FAILURE, 0, "Too many plugins");

    assert(endswith(path, LT_MODULE_EXT));
    tmpx = strrchr(path, '/');
    if (tmpx == NULL)
        tmpx = path;
    else
        tmpx++;
    inv.rec[inv.cnt].name = strndup(tmpx, strlen(tmpx) - strlen(LT_MODULE_EXT));

    inv.rec[inv.cnt].dll = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (inv.rec[inv.cnt].dll == NULL)
        error(EXIT_FAILURE, 0, "Unable to open plugin: %s", dlerror());

    tmp = dlsym(inv.rec[inv.cnt++].dll, "deo");
    if (tmp == NULL)
        error(EXIT_FAILURE, 0, "Unable to read plugin: %s", dlerror());

    inv.rec[inv.cnt - 1].plug = *tmp;
}

int
main(int argc, char *argv[])
{
    const char *plugindir = getenv("DEO_PLUGINS");
    int ret = EXIT_FAILURE;
    int max = 0;
    AUTO(DIR, dir);

    if (plugindir == NULL)
        plugindir = DEO_PLUGINS;

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    atexit(onexit);

    if (argc > 1) {
        const char *plugin = make_plugin_name(plugindir, argv[1]);
        if (access(plugin, R_OK) == 0) {
            load_plugin(plugin);
            return inv.rec[inv.cnt - 1].plug.cmd(argc, argv);
        } else {
            fprintf(stderr, "Unknown command: %s\n\n", argv[1]);
        }
    }

    dir = opendir(plugindir);
    if (dir == NULL)
        error(EXIT_FAILURE, errno, "Unable to open plugindir (%s)", plugindir);

    for (struct dirent *de = readdir(dir); de != NULL; de = readdir(dir)) {
        const char *plugin = make_plugin_name(plugindir, de->d_name);

        if (!deo_isreg(plugindir, de))
            continue;

        if (!endswith(de->d_name, LT_MODULE_EXT))
            continue;

        load_plugin(plugin);
    }

    qsort(inv.rec, inv.cnt, sizeof(struct record), cmp);

    for (size_t i = 0; i < inv.cnt; i++) {
        int tmp = strlen(inv.rec[i].name);
        if (tmp > max)
            max = tmp;
    }

    fprintf(stderr, "Usage: %s <command> ...\n\n", argv[0]);
    for (size_t i = 0; i < inv.cnt; i++) {
        /* Don't list plugins without summaries. */
        if (inv.rec[i].plug.summary == NULL)
            continue;

        fprintf(stderr, "%*s  %s\n", max + 4,
                inv.rec[i].name,
                inv.rec[i].plug.summary);
    }
    fprintf(stderr, "\n");

    return ret;
}
