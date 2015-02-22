# Petera

##### Welcome to Petera!
Petera is a system service and client for binding data to your local network.
The concept of this application is simple.

###### Online Operation
First, you encrypt some data to one or more particular servers. This data is
usually a key to decrypt some secondary data.

    $ petera anchor.pem encrypt one.me.com ... < key.txt > key.enc

Second, this key can be decrypted so long as your have access to the server it
was encrypted to.

    $ petera anchor.pem decrypt one.me.com ... < key.enc > key.txt

That's it!

You can encrypt the data to as many servers as you want in a single pass. The
encryption will not succeed unless all servers can be reached. Each server
should have a unique certificate; no sharing is required (and is strongly
discouraged). Server certificates can be rotated using standard CA tools like
certmonger.

If a payload is encrypted to multiple servers, only one of those servers is
required to be online for decryption. This lets you have load balancing and
redundancy for the decryption service.

###### Offline Operation

Petera encryption (but not, of course, decryption) can also be performed in
offline mode. Start by downloading the encryption certificate chain:

    $ petera anchor.pem fetch one.me.com > one.pem

Now you can perform encryption offline:

    $ petera anchor.pem encrypt one.pem < key.txt > key.enc

You can even mix online and offline mode:

    $ petera anchor.pem encrypt one.pem two.me.com < key.txt > key.enc

###### Security Considerations

Petera tries very hard to always do the right thing.

In particular, you may notice that the petera client ALWAYS takes anchor.pem
as the first argument. This is because we always validate whatever
certificates we encounter. This includes pem files stored locally. We force
you to use this argument to think carefully about which certificates you trust.

###### Petera Server

The Petera server is a simple systemd activated service. It listens on port
5700 by default. The most complex thing is getting the certificate setup
right. Here again, we test to make sure you don't expose sensitive certificates.

The Petera daemon takes three parameters:

1. A PEM file containing the TLS certificate chain and private key.
2. A PEM file containing the encryption certificate chain.
3. A directory of PEM files containing decryption certs/keys.

All communications are encrypted. Each Petera server offers only one
certificate chain for encryption, but can decrypt using multiple certificates.
This lets you set a new encryption key while still using old ones for
decryption.

The Petera server NEVER writes anything and is completely stateless. Feel free
to run it in a container if you like.

###### Future Improvements

Here is a list of things we could improve:

1. MAC encrypted data. We don't protect against on-disk tampering / corruption.
2. Check certificate expiration. Does OpenSSL do this for us?
3. Support CRL/OCSP checking and maybe OCSP stapling.

###### Concluding Thoughts

Peter is still a new project and may have some rough edges. We'd
love to hear your feedback!

###### Installation

    ./configure
    make
    sudo make install

###### Server Enablement

    sudo systemctl enable petera.socket
    sudo systemctl start petera.socket
