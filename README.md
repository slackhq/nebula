## What is Nebula?
Nebula is a scalable overlay networking tool with a focus on performance, simplicity and security.
It lets you seamlessly connect computers anywhere in the world. Nebula is portable, and runs on Linux, OSX, Windows, iOS, and Android.
It can be used to connect a small number of computers, but is also able to connect tens of thousands of computers.

Nebula incorporates a number of existing concepts like encryption, security groups, certificates,
and tunneling, and each of those individual pieces existed before Nebula in various forms.
What makes Nebula different to existing offerings is that it brings all of these ideas together,
resulting in a sum that is greater than its individual parts.

Further documentation can be found [here](https://nebula.defined.net/docs/).

You can read more about Nebula [here](https://medium.com/p/884110a5579).

You can also join the NebulaOSS Slack group [here](https://join.slack.com/t/nebulaoss/shared_invite/zt-2xqe6e7vn-k_KGi8s13nsr7cvHVvHvuQ).

## Supported Platforms

#### Desktop and Server

Check the [releases](https://github.com/slackhq/nebula/releases/latest) page for downloads or see the [Distribution Packages](https://github.com/slackhq/nebula#distribution-packages) section.

- Linux - 64 and 32 bit, arm, and others
- Windows
- MacOS
- Freebsd

#### Distribution Packages

- [Arch Linux](https://archlinux.org/packages/extra/x86_64/nebula/)
    ```
    $ sudo pacman -S nebula
    ```

- [Fedora Linux](https://src.fedoraproject.org/rpms/nebula)
    ```
    $ sudo dnf install nebula
    ```

- [Debian Linux](https://packages.debian.org/source/stable/nebula)
    ```
    $ sudo apt install nebula
    ```

- [Alpine Linux](https://pkgs.alpinelinux.org/packages?name=nebula)
    ```
    $ sudo apk add nebula
    ```

- [macOS Homebrew](https://github.com/Homebrew/homebrew-core/blob/HEAD/Formula/n/nebula.rb)
    ```
    $ brew install nebula
    ```

- [Docker](https://hub.docker.com/r/nebulaoss/nebula)
    ```
    $ docker pull nebulaoss/nebula
    ```

#### Mobile

- [iOS](https://apps.apple.com/us/app/mobile-nebula/id1509587936?itsct=apps_box&amp;itscg=30200)
- [Android](https://play.google.com/store/apps/details?id=net.defined.mobile_nebula&pcampaignid=pcampaignidMKT-Other-global-all-co-prtnr-py-PartBadge-Mar2515-1)

## Technical Overview

Nebula is a mutually authenticated peer-to-peer software defined network based on the [Noise Protocol Framework](https://noiseprotocol.org/).
Nebula uses certificates to assert a node's IP address, name, and membership within user-defined groups.
Nebula's user-defined groups allow for provider agnostic traffic filtering between nodes.
Discovery nodes allow individual peers to find each other and optionally use UDP hole punching to establish connections from behind most firewalls or NATs.
Users can move data between nodes in any number of cloud service providers, datacenters, and endpoints, without needing to maintain a particular addressing scheme.

Nebula uses Elliptic-curve Diffie-Hellman (`ECDH`) key exchange and `AES-256-GCM` in its default configuration.

Nebula was created to provide a mechanism for groups of hosts to communicate securely, even across the internet, while enabling expressive firewall definitions similar in style to cloud security groups.

## Getting started (quickly)

To set up a Nebula network, you'll need:

#### 1. The [Nebula binaries](https://github.com/slackhq/nebula/releases) or [Distribution Packages](https://github.com/slackhq/nebula#distribution-packages) for your specific platform. Specifically you'll need `nebula-cert` and the specific nebula binary for each platform you use.

#### 2. (Optional, but you really should..) At least one discovery node with a routable IP address, which we call a lighthouse.

Nebula lighthouses allow nodes to find each other, anywhere in the world. A lighthouse is the only node in a Nebula network whose IP should not change. Running a lighthouse requires very few compute resources, and you can easily use the least expensive option from a cloud hosting provider. If you're not sure which provider to use, a number of us have used $5/mo [DigitalOcean](https://digitalocean.com) droplets as lighthouses.

  Once you have launched an instance, ensure that Nebula udp traffic (default port udp/4242) can reach it over the internet.


#### 3. A Nebula certificate authority, which will be the root of trust for a particular Nebula network.

  ```
  ./nebula-cert ca -name "Myorganization, Inc"
  ```
  This will create files named `ca.key` and `ca.cert` in the current directory. The `ca.key` file is the most sensitive file you'll create, because it is the key used to sign the certificates for individual nebula nodes/hosts. Please store this file somewhere safe, preferably with strong encryption.

#### 4. Nebula host keys and certificates generated from that certificate authority
This assumes you have four nodes, named lighthouse1, laptop, server1, host3. You can name the nodes any way you'd like, including FQDN. You'll also need to choose IP addresses and the associated subnet. In this example, we are creating a nebula network that will use 192.168.100.x/24 as its network range. This example also demonstrates nebula groups, which can later be used to define traffic rules in a nebula network.
```
./nebula-cert sign -name "lighthouse1" -ip "192.168.100.1/24"
./nebula-cert sign -name "laptop" -ip "192.168.100.2/24" -groups "laptop,home,ssh"
./nebula-cert sign -name "server1" -ip "192.168.100.9/24" -groups "servers"
./nebula-cert sign -name "host3" -ip "192.168.100.10/24"
```

#### 5. Configuration files for each host
Download a copy of the nebula [example configuration](https://github.com/slackhq/nebula/blob/master/examples/config.yml).

* On the lighthouse node, you'll need to ensure `am_lighthouse: true` is set.

* On the individual hosts, ensure the lighthouse is defined properly in the `static_host_map` section, and is added to the lighthouse `hosts` section.


#### 6. Copy nebula credentials, configuration, and binaries to each host

For each host, copy the nebula binary to the host, along with `config.yml` from step 5, and the files `ca.crt`, `{host}.crt`, and `{host}.key` from step 4.

**DO NOT COPY `ca.key` TO INDIVIDUAL NODES.**

#### 7. Run nebula on each host
```
./nebula -config /path/to/config.yml
```

## Building Nebula from source

Make sure you have [go](https://go.dev/doc/install) installed and clone this repo. Change to the nebula directory.

To build nebula for all platforms:
`make all`

To build nebula for a specific platform (ex, Windows):
`make bin-windows`

See the [Makefile](Makefile) for more details on build targets

## Curve P256 and BoringCrypto

The default curve used for cryptographic handshakes and signatures is Curve25519. This is the recommended setting for most users. If your deployment has certain compliance requirements, you have the option of creating your CA using `nebula-cert ca -curve P256` to use NIST Curve P256. The CA will then sign certificates using ECDSA P256, and any hosts using these certificates will use P256 for ECDH handshakes.

In addition, Nebula can be built using the [BoringCrypto GOEXPERIMENT](https://github.com/golang/go/blob/go1.20/src/crypto/internal/boring/README.md) by running either of the following make targets:

    make bin-boringcrypto
    make release-boringcrypto

This is not the recommended default deployment, but may be useful based on your compliance requirements.

## Credits

Nebula was created at Slack Technologies, Inc by Nate Brown and Ryan Huber, with contributions from Oliver Fross, Alan Lam, Wade Simmons, and Lining Wang.



