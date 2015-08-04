#!/usr/bin/python3
#
# Copyright (c) 2015 Red Hat, Inc.
# Author: Nathaniel McCallum <npmccallum@redhat.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import atexit
import multiprocessing
import os
import shutil
import socket
import tempfile


class Server:
    @property
    def hp(self):
        if self.port is None:
            port = ''
        else:
            port = ':%d' % self.port

        return self.host + port

    def __file(self, path, srcs):
        with open(path, "w") as f:
            for src in srcs:
                with open(src) as g:
                    f.write(g.read())

    def __init__(self, tls, enc, dec, host, port=None):
        self.host = host
        self.port = port
        super(Server, self).__init__()

        self.__dir = tempfile.mkdtemp()
        atexit.register(lambda: shutil.rmtree(self.__dir))

        t = os.path.join(self.__dir, "tls.pem")
        e = os.path.join(self.__dir, "enc.pem")
        d = os.path.join(self.__dir, "dec.d")

        bin = os.environ['DEO_BIN']
        self.__arg = [bin, 'decryptd', '-t', t, '-e', e, '-d', d]

        os.mkdir(d)
        self.__file(t, tls)
        self.__file(e, enc)
        for name, srcs in dec.items():
            self.__file(os.path.join(d, name + '.pem'), srcs)

    def __enter__(self):
        def f(host, port):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((host, port))
            s.listen(1)

            conn = s.accept()[0]
            s.close()

            os.dup2(conn.fileno(), 3)
            conn.close()
            os.execv(self.__arg[0], self.__arg)

        port = self.port if self.port else 5700
        self.p = multiprocessing.Process(target=f, args=(self.host, port))
        self.p.start()

    def __exit__(self, type, value, tb):
        if self.p.is_alive():
            self.p.terminate()
