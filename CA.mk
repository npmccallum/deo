#
# This file contains rules to bring up a CA for testing.
# It only works on GNU make.
#

%/cnf: ca.cnf
	mkdir -p $(dir $@)/certs $(dir $@)/crl $(dir $@)/newcerts $(dir $@)/private $(dir $@)/csr
	touch $(dir $@)/index.txt
	echo 1000 > $(dir $@)/serial
	openssl genrsa -out $(dir $@)/private/cakey.pem 1024
	sed "s|@CA_DIR@|$(dir $@)|" $(srcdir)/ca.cnf > $@

PCA/cacert.pem: PCA/cnf
	openssl req -new -x509 -extensions v3_ca -key PCA/private/cakey.pem -out $@ -days 1 -subj "/CN=pca"

CCA/cacert.pem: PCA/cacert.pem CCA/cnf
	openssl req -new -key CCA/private/cakey.pem -out CCA/csr/cca.csr -subj "/CN=cca"
	openssl ca -batch -config PCA/cnf -extensions v3_ca -out $@ -infiles CCA/csr/cca.csr

CCA/private/%.pem: CCA/cacert.pem
	openssl genrsa -out $@ 1024

CCA/csr/%.csr: CCA/private/%.pem
	openssl req -new -key $< -out $@ -subj "/CN=$(basename $(notdir $@))"

CCA/newcerts/%.pem: CCA/csr/%.csr
	openssl ca -batch -config CCA/cnf -out $@ -infiles $<

SVC/peterad.pem: CCA/newcerts/localhost.pem CCA/cacert.pem CCA/private/localhost.pem
	mkdir -p SVC
	cat $^ > $@

SVC/enc/enc.pem: CCA/newcerts/enc.pem CCA/cacert.pem CCA/private/enc.pem
	mkdir -p SVC/enc 
	cat $^ > $@

clean-local:
	-rm -rf PCA CCA SVC