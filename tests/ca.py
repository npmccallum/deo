#!/usr/bin/python
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
import os
import shutil
import subprocess
import tempfile


class CA(object):
    CNF = """
HOME        = .
RANDFILE    = $ENV::HOME/.rnd

[ ca ]
default_ca    = CA_default

[ CA_default ]
dir           = %s
certs         = $dir/certs
crl_dir       = $dir/crl
database      = $dir/index.txt
new_certs_dir = $dir/newcerts
certificate   = $dir/ca.pem
serial        = $dir/serial
crlnumber     = $dir/crlnumber
crl           = $dir/crl.pem
private_key   = $dir/private/ca.pem
RANDFILE      = $dir/private/.rand

x509_extensions  = usr_cert
name_opt         = ca_default
cert_opt         = ca_default
default_days     = 1
default_crl_days = 30
default_md       = sha256
preserve         = no
policy           = policy_anything

[ policy_anything ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ req ]
default_bits       = 2048
default_md         = sha256
default_keyfile    = privkey.pem
x509_extensions    = v3_ca
string_mask        = utf8only

[ usr_cert ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:true
"""

    @property
    def certificate(self):
        return os.path.join(self.__dir, 'ca.pem')

    def __cmd(self, *args):
        with open("/dev/null", "w") as f:
            r = subprocess.call(("openssl",) + args, stdout=f, stderr=f)
            assert r == 0

    def __name(self):
        with open(os.path.join(self.__dir, 'serial')) as f:
            return f.read().strip()

    def key(self):
        out = os.path.join(self.__dir, 'private', '%s.pem' % self.__name())
        self.__cmd('genrsa', '-out', out)
        return out

    def csr(self, key, subj, *args):
        out = os.path.join(self.__dir, 'csr', '%s.csr' % self.__name())
        self.__cmd('req', '-new', '-key', key, '-subj', subj,
                   '-out', out, *args)
        return out

    def crt(self, csr, *args):
        out = os.path.join(self.__dir, 'newcerts', '%s.pem' % self.__name())
        self.__cmd('ca', '-batch', '-config', os.path.join(self.__dir, "cnf"),
                   '-in', csr, *args)
        return out

    def __init__(self, subj, parent=None):
        self.__dir = tempfile.mkdtemp()
        atexit.register(lambda: shutil.rmtree(self.__dir))

        for d in ('certs', 'crl', 'newcerts', 'private', 'csr'):
            os.mkdir(os.path.join(self.__dir, d))

        open(os.path.join(self.__dir, 'index.txt'), 'w').close()
        with open(os.path.join(self.__dir, 'serial'), 'w') as f:
            f.write('1000')

        with open(os.path.join(self.__dir, 'cnf'), 'w') as f:
            f.write(self.CNF % self.__dir)

        if parent is None:
            key = self.key()
            csr = self.csr(key, subj, '-x509', '-extensions', 'v3_ca')
            os.rename(key, os.path.join(self.__dir, 'private', 'ca.pem'))
            os.rename(csr, os.path.join(self.__dir, 'ca.pem'))

        else:
            key = parent.key()
            csr = parent.csr(key, subj)
            crt = parent.crt(csr, '-extensions', 'v3_ca')
            shutil.copyfile(key, os.path.join(self.__dir, 'private', 'ca.pem'))
            shutil.copyfile(crt, os.path.join(self.__dir, 'ca.pem'))
