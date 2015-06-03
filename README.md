# Deo

#### Welcome to Deo!
Deo is a system service and client for binding data to your local network.
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

This is precisely what Deo does. Let's look at how it works.

##### Online Operation
First, you encrypt some data to one or more particular servers. As mentioned
in the example above, this data is usually a key to decrypt some secondary
data.

    $ deo encrypt -a anchor.pem one.me.com ... < key.txt > key.enc

Second, this key can be decrypted so long as your have access to the server it
was encrypted to.

    $ deo decrypt < key.enc > key.txt

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

Deo encryption (but not, of course, decryption) can also be performed in
offline mode. Start by downloading the encryption certificate chain:

    $ deo query -a anchor.pem one.me.com > one.pem

Now you can perform encryption offline:

    $ deo encrypt -a anchor.pem one.pem < key.txt > key.enc

You can even mix online and offline mode:

    $ deo encrypt -a anchor.pem one.pem two.me.com < key.txt > key.enc

##### Security Considerations

Deo tries very hard to always do the right thing.

In particular, you may notice that the deo client takes anchor.pem
as an option. This is because we always validate whatever certificates we
encounter. This includes pem files stored locally. We force you to use this
argument to think carefully about which certificates you trust.

##### Deo Server

The Deo server is a simple systemd activated service. It listens on port
5700 by default. The most complex thing is getting the certificate setup
right. Here again, we test to make sure you don't expose sensitive
certificates.

All communications are encrypted. Each Deo server offers only one
certificate chain for encryption, but can decrypt using multiple certificates.
This lets you set a new encryption key while still using old ones for
decryption.

The Deo server NEVER writes anything and is completely stateless. Feel free
to run it in a container if you like.

###### Configuration

The Deo daemon requires only three configuration items:

1. A PEM file containing the TLS certificate chain and private key.
2. A PEM file containing the encryption certificate chain.
3. A directory of PEM files containing decryption certs/keys.

In the default install, these items are, respectively, located at:

1. /etc/deo/decryptd.pem
2. /etc/deo/encrypt.pem
3. /etc/deo/decrypt.d

On important note is necessary. The encryption certificate advertised to the
client MUST have a subject with a commonName that resolves to the decryption
server. This is the hostname that the client will use during decryption. This
hostname may be an IP address.

###### Enablement

To enable the server, just run the following as root:

    # systemctl enable deo-decryptd.socket
    # systemctl start deo-decryptd.socket

##### Using Deo with Disks
###### Prerequisites
First, you must have a Deo server running somewhere on your network. For
more information on this step, see the above section.

Second, you must have a client with LUKS disk encryption already enabled.

###### Setup
Both of the following commands are run as root.

First, we will configure the initramfs for networking. If you are using IPv4
DHCP, no configuration is needed. For other setups, please consult the dracut
documentation.

Second, we will add a new random key to the pre-existing LUKS encrypted disk
and then encrypt it using Deo in a known location. This command works
exactly like the encrypt command with the exception that a LUKS encrypted disk
must be specified:

    # deo cryptsetup -d /dev/<disk> -a <anchor> <target>

Finally, we need to rebuild the system's initramfs:

    # dracut -f

That's it! Once you reboot, the disk should unlock automatically so long as
one of the specified encryption targets is available.

##### Future Improvements

Here is a list of things we could improve:

1. Check certificate expiration. Does OpenSSL do this for us?
2. Support CRL/OCSP checking and maybe OCSP stapling.

##### Concluding Thoughts

Deo is still a new project and may have some rough edges. We'd
love to hear your feedback!

##### Installation

    ./configure
    make
    sudo make install
