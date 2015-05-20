# Petera

#### Welcome to Petera!
Petera is a system service and client for binding data to your local network.
The concept of this application is simple, but let's look at an example.

##### Use Case: Network-bound Automatic Disk Decryption
Suppose you have a disk with sensitive data. If it breaks, you can't just
send it back for repair. This could expose the data. Nor can you just throw
it away.

You could encrypt the disk. This would let you repair or discard the disk. But
now you have to remember a password and manually enter it on every boot. This
doesn't scale.

What you need is a way to encrypt the disk using a high entropy key and then
making it so that this key can be used automatically when you are on the
network, but not otherwise.

The solution to this problem is encrypting the key in such a way that it can
only be decrypted when you are on the network. Hence, you bind the key to
the network.

This is precisely what Petera does. Let's look at how it works.

##### Online Operation
First, you encrypt some data to one or more particular servers. As mentioned
in the example above, this data is usually a key to decrypt some secondary
data.

    $ petera encrypt -a anchor.pem one.me.com ... < key.txt > key.enc

Second, this key can be decrypted so long as your have access to the server it
was encrypted to.

    $ petera decrypt < key.enc > key.txt

That's it!

You can encrypt the data to as many servers as you want in a single pass. The
encryption will not succeed unless all servers can be reached. Each server
should have a unique certificate; no sharing is required (and is strongly
discouraged). Server certificates can be rotated using standard CA tools like
certmonger.

If a payload is encrypted to multiple servers, only one of those servers is
required to be online for decryption. This lets you have load balancing and
redundancy for the decryption service.

##### Offline Operation

Petera encryption (but not, of course, decryption) can also be performed in
offline mode. Start by downloading the encryption certificate chain:

    $ petera query -a anchor.pem one.me.com > one.pem

Now you can perform encryption offline:

    $ petera encrypt -a anchor.pem one.pem < key.txt > key.enc

You can even mix online and offline mode:

    $ petera encrypt -a anchor.pem one.pem two.me.com < key.txt > key.enc

##### Security Considerations

Petera tries very hard to always do the right thing.

In particular, you may notice that the petera client takes anchor.pem
as an option. This is because we always validate whatever certificates we
encounter. This includes pem files stored locally. We force you to use this
argument to think carefully about which certificates you trust.

##### Petera Server

The Petera server is a simple systemd activated service. It listens on port
5700 by default. The most complex thing is getting the certificate setup
right. Here again, we test to make sure you don't expose sensitive
certificates.

All communications are encrypted. Each Petera server offers only one
certificate chain for encryption, but can decrypt using multiple certificates.
This lets you set a new encryption key while still using old ones for
decryption.

The Petera server NEVER writes anything and is completely stateless. Feel free
to run it in a container if you like.

###### Configuration

The Petera daemon requires only three configuration items:

1. A PEM file containing the TLS certificate chain and private key.
2. A PEM file containing the encryption certificate chain.
3. A directory of PEM files containing decryption certs/keys.

In the default install, these items are, respectively, located at:

1. /etc/petera/decryptd.pem
2. /etc/petera/encrypt.pem
3. /etc/petera/decrypt.d

###### Enablement

To enable the server, just run the following as root:

    # systemctl enable petera-decryptd.socket
    # systemctl start petera-decryptd.socket

##### Using Petera with Disks
###### Prerequisites
First, you must have a Petera server running somewhere on your network. For
more information on this step, see the above section.

Second, you must have a client with LUKS disk encryption already enabled.

###### Setup
Both of the following commands are run as root.

The first command we will run simply adds a new random key to the pre-existing
LUKS encrypted disk and then encrypts it using Petera in a known location:

    # petera cryptsetup -d /dev/<disk> -a <anchor> <target>

Next, we will configure the initramfs for networking. For more information,
please consult the dracut documentation.

Finally, we need to rebuild the system's initramfs:

    # dracut -f

That's it! Once you reboot, the disk should unlock automatically so long as
one of the specified encryption target servers is available.

##### Future Improvements

Here is a list of things we could improve:

1. Check certificate expiration. Does OpenSSL do this for us?
2. Support CRL/OCSP checking and maybe OCSP stapling.

##### Concluding Thoughts

Petera is still a new project and may have some rough edges. We'd
love to hear your feedback!

##### Installation

    ./configure
    make
    sudo make install
