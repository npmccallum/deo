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

from ca import CA
from server import Server
import unittest
import os
import time
import subprocess


class Test(unittest.TestCase):
    def __makeServer(self, host, port=None):
        subj = '/CN=' + host + ('' if port is None else (':%d' % port))

        tls_key = self.ca_A_tls.key()
        tls_csr = self.ca_A_tls.csr(tls_key, subj)
        tls_crt = self.ca_A_tls.crt(tls_csr)

        enc_key = self.ca_A_enc.key()
        enc_csr = self.ca_A_enc.csr(enc_key, subj)
        enc_crt = self.ca_A_enc.crt(enc_csr)

        return Server([
            tls_key,
            tls_crt,
            self.ca_A_tls.certificate,
            self.ca_A.certificate,
        ], [
            enc_crt,
            self.ca_A_enc.certificate,
            self.ca_A.certificate,
        ], {
            'decrypt': [
                enc_key,
                enc_crt,
                self.ca_A_enc.certificate,
                self.ca_A.certificate,
            ]
        }, host, port)

    def __query(self, ca, srv):
        cmd = "$DEO_BIN query -a %s %s" % (ca.certificate, srv.hp)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        try:
            out, err = p.communicate(timeout=5)
        except TimeoutExpired:
            p.kill()
            out, err = p.communicate()
        sep = "-----BEGIN CERTIFICATE-----".encode('utf-8')
        return p.returncode == 0 and len(out.split(sep)) == 4

    def __encrypt(self, input, ca, *argv):
        arg = " ".join(map(lambda x: x.hp, argv))
        cmd = "$DEO_BIN encrypt -a " + ca.certificate + " " + arg

        p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, shell=True)
        try:
            out, err = p.communicate(input=input, timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()

        return None if p.returncode != 0 else out

    def __targets(self, input):
        p = subprocess.Popen("$DEO_BIN targets", stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, shell=True)
        try:
            out, err = p.communicate(input=input, timeout=5)
        except TimeoutExpired:
            p.kill()
            out, err = p.communicate()

        if p.returncode != 0:
            return None

        return out.decode('utf-8').strip().split("\n")

    def __decrypt(self, input):
        p = subprocess.Popen("$DEO_BIN decrypt", stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, shell=True)
        try:
            out, err = p.communicate(input=input, timeout=5)
        except TimeoutExpired:
            p.kill()
            out, err = p.communicate()

        return None if p.returncode != 0 else out

    def setUp(self):
        self.ca_A = CA('/CN=A')
        self.ca_B = CA('/CN=B')

        self.ca_A_tls = CA('/CN=A_tls', self.ca_A)
        self.ca_A_enc = CA('/CN=A_enc', self.ca_A)

        self.srvA = self.__makeServer('localhost')
        self.srvB = self.__makeServer('localhost', 5701)

    def testQuery(self):
        "Test that basic querying works."

        with self.srvA:
            assert self.__query(self.ca_A, self.srvA)
        with self.srvB:
            assert self.__query(self.ca_A, self.srvB)

    def testQueryValidation(self):
        "Test that queries fail when a certificate doesn't validate."

        with self.srvA:
            assert not self.__query(self.ca_B, self.srvA)
        with self.srvB:
            assert not self.__query(self.ca_B, self.srvB)
        with self.srvA:
            assert not self.__query(self.ca_A_tls, self.srvA)
        with self.srvB:
            assert not self.__query(self.ca_A_tls, self.srvB)
        with self.srvA:
            assert not self.__query(self.ca_A_enc, self.srvA)
        with self.srvB:
            assert not self.__query(self.ca_A_enc, self.srvB)

    def testEncTargetsDec(self):
        "Test that basic multi-target encryption/decryption works."

        pt = "hello".encode('utf-8')

        with self.srvA:
            with self.srvB:
                out = self.__encrypt(pt, self.ca_A, self.srvA, self.srvB)

        assert out is not None
        assert self.__targets(out) == [self.srvA.hp, self.srvB.hp]

        with self.srvA:
            assert self.__decrypt(out) == pt

        with self.srvB:
            assert self.__decrypt(out) == pt

        assert self.__decrypt(out) is None

    def testEncValidation(self):
        "Test that encryption fails when a certificate doesn't validate."

        pt = "hello".encode('utf-8')

        with self.srvA:
            assert self.__encrypt(pt, self.ca_B, self.srvA) is None
        with self.srvA:
            assert self.__encrypt(pt, self.ca_A_tls, self.srvA) is None
        with self.srvA:
            assert self.__encrypt(pt, self.ca_A_enc, self.srvA) is None

if __name__ == '__main__':
    unittest.main()
