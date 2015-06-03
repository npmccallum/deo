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

#include "misc.h"

#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <error.h>
#include <unistd.h>

bool
deo_validate(const STACK_OF(X509) *anchors, STACK_OF(X509) *chain)
{
    AUTO(X509_STORE_CTX, sctx);
    AUTO(X509_STORE, store);

    if (chain == NULL || sk_X509_num(chain) == 0)
        return false;

    store = X509_STORE_new();
    if (store == NULL)
        return false;

    if (anchors == NULL || sk_X509_num(anchors) == 0) {
        if (X509_STORE_set_default_paths(store) <= 0)
            return false;
    } else {
        for (int i = 0; i < sk_X509_num(anchors); i++) {
            X509 *cert = sk_X509_value(anchors, i);
            X509_STORE_add_cert(store, cert);
        }
    }

    sctx = X509_STORE_CTX_new();
    if (sctx == NULL)
        return false;

    if (X509_STORE_CTX_init(sctx, store, sk_X509_value(chain, 0), chain) <= 0)
        return false;

    return X509_verify_cert(sctx) > 0;
}

bool
deo_load(FILE *fp, STACK_OF(X509) *certs)
{
    AUTO_STACK(X509_INFO, infos);

    infos = PEM_X509_INFO_read(fp, NULL, NULL, NULL);
    if (infos == NULL)
        return false;

    for (int i = 0; i < sk_X509_INFO_num(infos); i++) {
        X509_INFO *info = sk_X509_INFO_value(infos, i);
        X509 *cert;

        if (info->x509 == NULL)
            continue;

        cert = X509_dup(info->x509);
        if (cert == NULL)
            return false;

        if (sk_X509_push(certs, cert) <= 0) {
            X509_free(cert);
            return false;
        }
    }

    return true;
}

DEO_MSG *
deo_request(const STACK_OF(X509) *anchors, const ASN1_UTF8STRING *target,
               const DEO_MSG *req)
{
    char trgt[target->length + 1];
    AUTO(SSL_CTX, ctx);
    AUTO(BIO, io);

    memset(trgt, 0, sizeof(trgt));
    memcpy(trgt, target->data, target->length);

    if (anchors == NULL || sk_X509_num(anchors) == 0)
        return NULL;

    ctx = SSL_CTX_new(TLSv1_2_client_method());
    if (ctx == NULL)
        return NULL;

    for (int i = 0; anchors != NULL && i < sk_X509_num(anchors); i++) {
        X509 *cert = sk_X509_value(anchors, i);
        X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), cert);
    }

    io = BIO_new_ssl_connect(ctx);
    if (io == NULL)
        return NULL;

    BIO_set_conn_port(io, DEO_SOCKET);
    BIO_set_ssl_mode(io, SSL_MODE_AUTO_RETRY);
    if (BIO_set_conn_hostname(io, trgt) <= 0)
        return NULL;

    if (BIO_do_connect(io) <= 0)
        return NULL;

    if (BIO_do_handshake(io) <= 0)
        return NULL;

    if (ASN1_item_i2d_bio(&DEO_MSG_it, io, (DEO_MSG *) req) <= 0)
        return NULL;

    return ASN1_item_d2i_bio(&DEO_MSG_it, io, NULL);
}

bool
deo_anchors(char c, const char *arg, STACK_OF(X509) **misc)
{
    AUTO_STACK(X509, tmp);
    AUTO(FILE, file);

    if (arg == NULL || misc == NULL)
        return false;

    file = fopen(arg, "r");
    if (file == NULL)
        return false;

    tmp = *misc == NULL ? sk_X509_new_null() : *misc;
    if (tmp == NULL)
        return false;

    if (!deo_load(file, tmp))
        return false;

    if (*misc == NULL)
        *misc = STEAL(tmp);

    return true;
}

bool
deo_getopt(int argc, char **argv, const char *opt, const char *keep, ...)
{
    char options[strlen(opt) + strlen(keep) + 1];
    const int ind = ++optind;
    char *forget[argc];
    char *retain[argc];
    size_t fcnt = 0;
    size_t rcnt = 0;
    va_list ap;

    memset(forget, 0, sizeof(forget));
    memset(retain, 0, sizeof(retain));
    strcpy(options, opt);
    strcat(options, keep);

    for (int c; (c = getopt(argc, argv, options)) != -1; ) {
        const char *k = strchr(keep, c);
        const char *o = strchr(opt, c);
        bool found = false;

        if ((k != NULL) == (o != NULL)) {
            return false;
        } else if (k != NULL) {
            retain[rcnt++] = argv[optind - 2];
            if (k[1] == ':')
                retain[rcnt++] = argv[optind - 1];
        } else if (o != NULL) {
            forget[fcnt++] = argv[optind - 2];
            if (o[1] == ':')
                forget[fcnt++] = argv[optind - 1];
        }

        va_start(ap, keep);
        for (size_t i = 0; options[i] != '\0' && !found; i++) {
            deo_parse p;
            void *m;

            if (i == 0 && strchr("+-", options[i]) != NULL)
                continue;

            if (options[i] == ':')
                continue;

            p = va_arg(ap, deo_parse);
            m = va_arg(ap, void *);

            if (options[i] != c)
                continue;

            found = true;
            if (p == NULL)
                return false;

            if (!p(c, options[1 + 1] == ':' ? optarg : NULL, m))
                return false;
        }
        va_end(ap);

        if (!found)
            return false;
    }

    for (size_t i = 0; i < fcnt; i++)
        argv[ind + i] = forget[i];
    for (size_t i = 0; i < rcnt; i++)
        argv[ind + fcnt + i] = retain[i];

    optind -= rcnt;
    return true;
}

int
deo_run(char *argv[], int in, int out)
{
    char path[PATH_MAX];
    int status = 0;
    pid_t pid;

    strncpy(path, argv[0], sizeof(path));
    if (strchr(argv[0], '/') != NULL) {
        if (realpath(argv[0], path) == NULL)
            return errno;
    }

    pid = fork();
    if (pid < 0)
        return errno;

    if (pid == 0) {
        if (dup2(in, STDIN_FILENO) < 0)
            exit(errno);

        if (dup2(out, STDOUT_FILENO) < 0)
            exit(errno);

        execvp(path, argv);
        exit(errno);
    }

    if (waitpid(pid, &status, 0) != pid)
        return errno;

    return WEXITSTATUS(status);
}

int
deo_pipe(int *rend, int *wend)
{
    int in[2];

    if (pipe(in) != 0)
        return errno;

    *rend = in[0];
    *wend = in[1];
    return 0;
}

bool
deo_isreg(const char *dir, struct dirent *de)
{
    char path[PATH_MAX];
    struct stat st;
    int ret;

    switch (de->d_type) {
    case DT_REG:
        return true;

    case DT_UNKNOWN:
        ret = snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        if (ret < 0 || ret == sizeof(path))
            break;

        if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
            return true;

    default:
        break;
    }

    return false;
}
