# Nebula Overlay Network
Thanks for taking a look at Nebula! It's an 
[overlay network](https://en.wikipedia.org/wiki/Overlay_network), allowing you 
to present contiguious IPv4 addresses (like 192.0.2.1/24, 192.0.2.2/24 and so 
on) in hosts on separated network.

Hosts can talk to each other, without having to go via a central peer (unlike 
traditional hub-and-spoke VPN connections) and communication is encrypted 
between peers, authenticated via a central Public/Private Key service.

## Some notes on this documentation
These documents are being written with a Linux bias. In the examples below, the 
binaries will be stored in `/opt/nebula`, and the configuration in 
`/etc/nebula`. If your environment uses different conventions, that's fine too! 
If something specific comes up that is different between Linux and another 
platform, it will be specifically called out!

Some sample config files are available. You might find them useful!
- [A simple lighthouse with a public IP of 198.51.100.10 and nebula IP of 192.0.2.1](simple-config-lighthouse.yml)
- [A simple node with a public IP in the CIDR 198.51.100.0/24](simple-config-node.yml)
- [A fully documented configuration file](../examples/config.yml)

## IP Addresses used in this documentation

This document will also use some explicit "TEST-NET-1" addresses 
(192.0.2.0/24), "TEST-NET-2" addresses (198.51.100.0/24) and "TEST-NET-3" 
addresses (203.0.113.0/24). These addresses **should not be used** anywhere 
except for in documentation. There are also a few non-routable network
addresses for private networks (RFC1918) (10.0.0.0/8, 172.16.0.0/12 and
192.168.0.0/16). These are likely to be in use in your network, but also should
not be used verbatim as they are likely to conflict with YOUR network.

**PLEASE DON'T COPY THE EXAMPLES VERBATIM!** Use your own IP Schema!

## Improving this documentation 

If you have questions about this documentation, please feel free to raise an
issue on the [issue tracker](https://github.com/slackhq/nebula/issues), and 
include the keyword 
"[Documentation](https://github.com/slackhq/nebula/issues?utf8=%E2%9C%93&q=Documentation)".
Alternatively, update this file via a Pull Request!

## Getting Started
The first thing to do is to get the relevant executable binary file for your 
operating system of choice. These can be found on the 
[releases page](https://github.com/slackhq/nebula/releases/latest). Download 
the binaries to your system, and place them in an appropriate place in your 
file system - these examples assume you're using `/opt/nebula`.

You should also create the path where you'll be putting your certificates. 
Let's do that first of all. 

`mkdir -p /etc/nebula`

### Certificate Authority (CA)
Next you need to create at least one Certificate Authority (CA). A CA is used 
by the nodes in the network to authenticate that the next node is allowed to 
communicate with this one. The examples that follow assume a Linux operating 
system, but most of these commands will work cross-platform.

Let's create the CA: 

`cd /etc/nebula ; /opt/nebula/nebula-cert ca -name my_certificate_authority` 

When you run this command, it will create two files - `/etc/nebula/ca.key` 
and `/etc/nebula/ca.crt`. These are your 
[public and private keys](https://en.wikipedia.org/wiki/Public-key_cryptography) 
for the Certificate Authority.

**YOU MUST KEEP THE FILE `ca.key` PROTECTED**

### Client Certificates
At this point, you need to have a bit of an idea on just how your network 
should look! Do you want every trusted host to reach every trusted host? 
Do you only want "management" machines to be able to reach "servers"? Do you 
only want your "web servers" to be able to reach your "database servers" 
or... something more?! This will define how you build your next few steps.

Most people are going to want to segregate things a little bit, so this next 
block will be based on a model where your "client" machines are in a group 
called "client" and your servers are in a group called "servers". "Clients" 
can talk to "servers" on any port, but "servers" can't initiate connections 
to "clients".

So, let's build our first node certificate. The simplest way to do this is on 
the CA server, like this: 

`cd /etc/nebula ; /opt/nebula/nebula-cert sign -name client1 -ip 192.0.2.1/24 -groups client`

Fab. 

This creates a `client1.key` and `client1.crt` file, and then uses the `ca.key` 
to sign the `client1.crt` file. This key pair, much like the CA, is valid for 
1 year. There will be some notes later on how to do things to mitigate against 
issues with these certificates expiring.

You need to transfer the `client1.*` and `ca.crt` file to your client. 

Now let's build your second node certificate - this is for your server. 

`cd /etc/nebula ; /opt/nebula/nebula-cert sign -name server1 -ip 192.0.2.128/24 -groups server`

Great! We've got certificates to work between nodes! Now, let's build your 
configuration!

### Client configuration
There's an [example configuration file](/examples/config.yml) in the repository
but this is going to expand out some details on each block to help you decide
if you want to use these features!

Let's start at the top!

#### PKI

```yaml
pki:
  ca: /etc/nebula/ca.crt
  cert: /etc/nebula/host.crt
  key: /etc/nebula/host.key
  #blacklist:
  # - c99d4e650533b92061b09918e838a5a0a6aaee21eed1d12fd937682865936c72
```

This block here tells your file where it can find your PKI files.

There's also a commented out section called "blacklist". A blacklist is a
collection of certificates we MUST NOT talk to - typically compromised or lost
machines. Those machines must not be able to talk to the network, and so should
be added as a list of "fingerprints" to ignore.

<!-- TODO: Document how to get the fingerprints -->

[For extra credit, have a look at how to store multiple CA files or 
certificates inline or in their own single 
files](#Inline-PKI-and-Multiple-PKI-content).

#### Static Host Map and Lighthouses

Before we address this block, we need to briefly discuss "Lighthouses". A
"lighthouse" is used to work out what addresses are valid in your network, and 
how to connect to those nodes in the network. If you can't see at least one of
the same "lighthouses" as the another node you want to talk to, you won't be
able to connect to that node! You must run at least one "lighthouse" in your
Nebula network, and preferably more than one!

Each node that is a "lighthouse" mustn't "know" about any other "lighthouses",
so the "static_host_map" below, and the "lighthouse" "hosts" lists must both be
empty on "Lighthouses".

Lighthouses need to be generally "accessible" on the internet, on a specific 
port. Nebula has picked UDP/4242 as the port to provide, so if you're planning
to run a Lighthouse behind your home DSL, or on a cloud provided virtual 
machine, you must expose this port!

To find those Lighthouses, we need to tell your node about it! Because all
Nebula addresses are static, it means we can identify that node explicitly.

Let's show an example of this with four lighthouses using all the available
ways of addressing them:

```yaml
static_host_map:
  "192.0.2.1": ["198.51.100.1:4242"]
  "192.0.2.2": ["203.0.113.30:12345"]
  "192.0.2.3": 
    - "198.51.100.50:4242"
    - "203.0.113.80:4242"
  "192.0.2.4": ["mylighthouse.example.com:4242"]
```

So, here we have, in order:

1. A "simple" host map, on the default port (4242)
2. A "simple" host map, on a non-standard port (12345) - perhaps there's some 
odd NAT requirements here?
3. A host map with two IP addresses (perhaps one is a public address and the
other is a private address?)
4. A host map with a DNS name (perhaps the host doesn't have a static IP and so
they put it on a Dynamic DNS service?)

Remember that the more lighthouses you have, the more likely you are to find
the other nodes on the network! If you can, make every public node a 
lighthouse!

On a lighthouse node, this block will instead look like this:

```yaml
static_host_map:

```

After the `static_host_map` block is a section labelled "`lighthouse`". Let's 
dig into this section.

```yaml
lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - "192.0.2.1"
    - "192.0.2.2"
    - "192.0.2.3"
    - "192.0.2.4"
```

Because this node isn't a lighthouse, we need to tell it that it isn't! We also
need to tell it how often to tell the Lighthouse it's there, and to ask about
what else is on the network. And lastly, we need to tell it which Nebula IPs it
needs to talk to. We defined 4 addresses in the "static_host_map" above, so we
define those same four here.

If this node were a lighthouse, it'd look a bit different!

```yaml
lighthouse:
  am_lighthouse: true
  interval: 60
  hosts:

```

[For extra credit, there's a section in the example config talking about
DNS](#DNS-on-Lighthouses).

#### Inter-Nebula Communication

Every service binds to a host and a port, and Nebula is no different. If your
Nebula node is going to be a lighthouse, you must define the port here (and
your connecting nodes will need to specify that port in their static_host_map.
Most people will probably bind to host 0.0.0.0 (all interfaces) but if you
know you need not do that, you'll know what it should be set to.

This is the setting for Lighthouse nodes, or where you have a restrictive set 
of network policies or security groups configured:

```yaml
listen:
  host: 0.0.0.0
  port: 4242
punchy: true
punch_back: true
```

For roaming clients, or nodes which don't require specific ports being opened 
on firewall rules or security groups (particularly behind multiple NATting 
appliances), this is a better setting:

```yaml
listen:
  host: 0.0.0.0
  port: 0
punchy: true
punch_back: true
```

[If you are suffering from throughput or buffer issues, there are details on
settings you can adjust in the extra credit
section](#Tweaking-the-Nebula-Communication-Parameters).

#### Interface

```yaml
tun:
  dev: nebula1
```

<!-- TODO: Confirm whether you need to specify the tun/dev name on Non-Linux OS? -->

[In the `tun` block, we only *need* to set one value, and that's the device name 
(or `dev`). While it's possible to tweak these settings, the "best" defaults
are already set. You can have a peak at your options in the 
Extra Credit section below](#Configuring the Interface settings).

#### Protecting the nodes!

All the best network devices have firewalls! There's a default set of timeouts
for TCP and UDP packets (12 minutes and 3 minutes, respectively) and a 10
minute "default" timeout for any other packet type. In the below config block
we extend the TCP timeout to 120 hours (which is excessive!) and the UDP 
timeout to 30 minutes.
<!-- based on https://github.com/slackhq/nebula/issues/128 -->

Aside from those incomplete connection timeouts, there are also a set of rules.
Rules are basically a set of options for matching packets to allowed traffic
patterns for this node. Here's a basic set of rules:

```yaml
firewall:
  conntrack:
    tcp_timeout: 120h
    udp_timeout: 30m
    default_timeout: 10m
    max_connections: 100000

  outbound:
    - port: any
      protocol: any
      host: any
  inbound:
    - port: 22
      protocol: tcp
      host: any
    - protocol: icmp
      host: any
```

Any packet that doesn't match a packet here is dropped. If you're used to
security groups on AWS or Azure will be familiar with this convention!

Port numbers can be:
- Omitted (default value of `any` if omitted)
- The number `0` or the word `any` meaning any port
- A single number: `80` or `443` or `22` meaning that exact port number
- A range: `1-1023` meaning any port in that range

Protocols are:
- Omitted (default value of `any` if omitted)
- any (meaning any IP protocol)
- tcp
- udp
- icmp

Finally, the way to match what nodes are allowed to initiate the connection or
to be the target of one (depending on whether this is an "inbound" and 
"outbound" connection) comes down to the following keywords:
- host: `any` or a node's name from the `nebula-cert` tool
- group: `any` or a group name from the `nebula-cert` tool
- groups: a dictionary of viable group names, AND'd together - discussed after
- cidr: Some CIDR mask, e.g. `10.0.0.0/8` or `192.0.2.0/24` or 
`198.51.100.100/32`

Here, we mention "groups" as being "AND'd" together. Let's look at some ideas
of what that would mean.

Let's create some certificates for nodes and then identify whether they match
any rules!

1. `nebula-cert sign -name simon-laptop -groups admin,laptop,db -ip 192.0.2.1/24`
2. `nebula-cert sign -name simon-desktop -groups admin,desktop,db -ip 192.0.2.2/24`
3. `nebula-cert sign -name stephen-laptop -groups admin,laptop,web -ip 192.0.2.3/24`
4. `nebula-cert sign -name stephen-desktop -groups admin,desktop,web -ip 192.0.2.4/24`
5. `nebula-cert sign -name web-server -groups server,web -ip 192.0.2.128/24`
6. `nebula-cert sign -name db-server -groups server,db -ip 192.0.2.129/24`
7. `nebula-cert sign -name brian-laptop -groups ceo,laptop -ip 192.0.2.64/24`
8. `nebula-cert sign -name sharon-laptop -groups ceo,laptop -ip 192.0.2.65/24`

Here are some rules (assuming each non-Result line has the same result as the
previous Result statement):
```yaml
inbound:
  # Result: All nodes listed above
  - cidr: 192.0.2.0/24 # CIDR matches all 192.0.2.x addresses
  - host: any
  - group: any

  # Result: simon-laptop, stephen-laptop only
  - groups:
      - admin
      - laptop

  # Result: simon-laptop, simon-desktop, stephen-laptop, stephen-desktop only
  - cidr: 192.0.2.0/26 # CIDR matches all addresses in the range 192.0.2.0-192.0.2.63
  - group: admin

  # Result: web-server, db-server only
  # Note that group: <onename> == groups: ["<onename>"] == groups: \n  - <onename>
  - groups:
      - server
  
  # Result: simon-laptop, stephen-laptop, brian-laptop, sharon-laptop only
  # Note that group: <onename> == groups: ["<onename>"] == groups: \n  - <onename>
  - group: laptop

  # Result: db-server only
  - groups:
      - server
      - db
  
  # Result: None
  - groups:
      - users
  - groups:
      - ceo
      - desktop
  - groups:
      - admin
      - server
```

[There are some extra firewall options around certificates. Check out the
extra credit section on Firewall Certificates](#Firewall-Certificates) below.

#### Logging and Statistics

By default, Nebula logs just `info` level records to `stdout` as text records.

[You can enable extra formats and statistic logging for Graphite and Nebula. Details
for these are in the Extra Credit section below!](#Statistics-and-Debugging)

## Extra credit!

### Inline PKI and Multiple PKI content
[There is another way you can write the PKI block](https://github.com/slackhq/nebula/issues/111),
if you want to have less files to work with!

```yaml
pki:
  ca: |
    -----BEGIN NEBULA CERTIFICATE-----
    abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefgh
    ijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefghijklmnop
    qrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefghijklmnopqrstuvwx
    yz=
    -----END NEBULA CERTIFICATE-----
  cert: |
    -----BEGIN NEBULA CERTIFICATE-----
    abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefgh
    ijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefghijklmnop
    qrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefghijklmnopqrstuvwx
    yzABCDEFGHIJKLMNOPQRSTUVWXYZ123==
    -----END NEBULA CERTIFICATE-----
  key: |
    -----BEGIN NEBULA X25519 PRIVATE KEY-----
    abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP==
    -----END NEBULA X25519 PRIVATE KEY-----
```

Because these certificates expire after one year, you may want to have several
files in one block. You can do this too, like this (example just shows the
"ca" value, but the same is true for cert too):

```yaml
pki:
  ca: |
    -----BEGIN NEBULA CERTIFICATE-----
    abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefgh
    ijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefghijklmnop
    qrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefghijklmnopqrstuvwx
    yz=
    -----END NEBULA CERTIFICATE-----
    -----BEGIN NEBULA CERTIFICATE-----
    abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefgh
    ijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefghijklmnop
    qrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefghijklmnopqrstuvwx
    yzABCDEFGHIJKLMNOPQRSTUVWXYZ123==
    -----END NEBULA CERTIFICATE-----
```

Alternatively, store a single file (`/etc/nebula/ca.crt`) with all these CA
files in it.

### DNS on Lighthouses

On a lighthouse node, you can also define the following:

```yaml
lighthouse:
  am_lighthouse: true
  serve_dns: true
  dns:
    host: 0.0.0.0
    port: 53
  interval: 60
  hosts:

```

As per [these notes](https://github.com/slackhq/nebula/issues/110), You can use 
this to resolve the Certificate Names of other nodes on the network, for 
example, when we defined `client` and `server` before, you can do a DNS lookup
against the lighthouse (with DNS features enabled) to find the Nebula IP of 
that node - so `dig @192.0.2.1 server` would return `192.0.2.2`. You can also 
do a DNS lookup for a TXT record against the IP address - 
`dig @192.0.2.1 -t TXT 192.0.2.2` to find the certificate details for that 
node.

While you may be tempted to run the DNS resolver on non-Lighthouse nodes, the 
node is unlikely to know about all the other hosts on the network, unless it is
trying to communicate with all of them.

You should be aware, however, that many recent Linux versions run a DNS 
resolver, so you would need to either prevent that DNS resolver from running, 
or run the Nebula resolver on a separate IP or port. These options are far 
outside the remit of this document, however!

### Tweaking the Nebula Communication Parameters

```yaml
listen:
  host: 0.0.0.0
  port: 4242
  #batch: 64
  #read_buffer: 10485760
  #write_buffer: 10485760

punchy: true
#punch_back: true
#cipher: chachapoly
#local_range: "172.16.0.0/24"
```

<!-- TODO: Explain why you'd set the batch and buffer values -->
<!-- TODO: Explain what "punchy" and "punch_back" do, and why you might want to disable them! -->
<!-- TODO: Explain other cipher options, and why you might select them -->
<!-- TODO: Explain what local_range does -->

### Configuring the Interface settings

```yaml
tun:
  dev: nebula1
  drop_local_broadcast: false
  drop_multicast: false
```

Nebula can forward broadcast messages and multicast messages to other nodes in
the network. If you don't know what these are or why you'd want to change them,
then you should just leave them as the default values

```yaml
tun:
  dev: nebula1
  tx_queue: 500
```

<!-- TODO: Explain why you'd set the tx_queue -->

```yaml
tun:
  dev: nebula1
  mtu: 1300
  routes:
    - mtu: 8800
      route: 10.0.0.0/8
    - mtu: 1200
      route: 10.0.5.0/24
```

MTU (the Maximum Transfer Unit) is the size of an IP Packet, and this is 
typically set to 1500 bytes. Some networks enable "Jumbo Packets" which can be
much larger - in some cases up to 4GiB. If you have a network with these larger
MTU sizes (or, if you need something smaller than 1500 bytes) these need to be
set here. This essentially says "My unencrypted packet to 10.0.0.0/8 will go
via a network with a MTU of 8800 bytes, except for 10.0.5.0/24 which will go
via a network with a MTU of 1200 byes."

The default value for any "tun" interface is 1300 bytes. If you need to set
this to something smaller. Do so here!

### Carrying traffic for Non-Nebula connected services

```yaml
tun:
  dev: nebula1
  unsafe_routes:
    - route: 203.0.113.0/24
      via: 192.0.2.15
    - route: 198.51.100.0/24
      via: 192.0.2.30
      mtu: 3000
```

While Nebula is awesome, it might be useful to connect *through* a nebula node
to somewhere else on your network, for example, if you have a set of network
appliances (switches, routers, etc.) and you know that Nebula won't be ported
to that platform any time soon, you could, perhaps, have a specific device act
as a router to access that environment. In this block here, we define two
nebula nodes as routers to provice access to blocks which live behind them.

The down side to doing this is that you'd need to provide this routing
information on every node that needs to access them (perhaps, only the network
teams need to access those switches - so they'd have special config files to
get to those network blocks). The unsafe network segments in question, for
example 203.0.113.0/24 above, would also need to have a route back to the
nebula network (perhaps 203.0.113.2/24) which would need to be added as a
static route, or something the router in that subnet can direct.

You also need to configure your certificate to show it can carry this "unsafe"
traffic, like these examples (using the `-subnets` switch):

```
nebula-cert sign -name node_15 -ip 192.0.2.15/24 -subnets 203.0.113.0/24 -groups gateways,backup_service,management
nebula-cert sign -name node_30 -ip 192.0.2.30/24 -subnets 198.51.100.0/24 -groups gateways,switch_management,management
```

On the node that is carrying the "unsafe" traffic (e.g. 192.0.2.15), any
firewall rules that apply to that node will also apply to any traffic behind
that node. For example, if your firewall stanza looks (abbreviated) like this:

```yaml
firewall:
  inbound:
    - port: 22
      protocol: tcp
      host: any
```

Then any Nebula host can reach through this node to your "unsafe" networks
behind it. [It is recommended that you add additional firewall rules to the
hosts in the unsafe network.](https://github.com/slackhq/nebula/issues/142#issuecomment-570250934)

This does also mean that you can centrally host services in Nebula (perhaps
a syslog service, or a backup service) and your unsafe networks can also
connect back to them via a Nebula router.

### Running an SSH based service manager

```yaml
sshd:
  enabled: true
  listen: 127.0.0.1:2222
  host_key: ./ssh_host_ed25519_key
  authorized_users:
    - user: bloggsf
      keys:
        - "<SSH KEY 1>"
        - "<SSH KEY 2>"
    - user: smithj
      keys: "<A SSH KEY>"
```

Sometimes it's useful to get remote access to the service manager, to be able
to interrogate tunnels which are up, and to restart things. To support this,
the Nebula Developers created a service manager service, running in SSH. To
enable this, you need to turn on a few options.

1. Create the block "sshd", and set "enabled" to true.
1. Decide where you want to expose the service. To see how it runs, you might
want to put the service _just_ on a port on "Localhost". You might, instead,
want to run it on a public interface and port. There are security risks here
but, it's your service... <!-- TODO: List security concerns in exposing SSHD -->
1. Create an SSH Host Key. Use this command to create it:
`ssh-keygen -t ed25519 -f /etc/nebula/ssh_host_ed25519_key -N "" < /dev/null`
1. List all the authorized users and keys they use. In the example block above
there are two users, `bloggsf` and `smithj`. `bloggsf` has two SSH keys to
their username, while `smithj` has one.

### Firewall Certificates

Sometimes, you might want to delegate certificate responsibilities to nodes in
a specific network segment. Perhaps your servers all have a CA node, while your
user machines all get their certificates from another CA node. How could we
use this?

When you create your CA certificates, you should specify a name for each CA,
like this: `nebula-cert ca -name server-ca` and `nebula-cert ca -name user-ca`

Next, in your PKI section for each node, you need to add all the CA 
certificates, like this:
<!-- based on https://github.com/slackhq/nebula/issues/111 -->

```yaml
pki:
  ca: |
    -----BEGIN NEBULA CERTIFICATE-----
    <SERVERS CA CERTIFICATE>
    -----END NEBULA CERTIFICATE-----
    -----BEGIN NEBULA CERTIFICATE-----
    <USERS CA CERTIFICATE>
    -----END NEBULA CERTIFICATE-----
  cert: /etc/nebula/node.crt
  key: /etc/nebula/node.key
```

Lastly, in your firewall rules section, you might have this for your servers:

```yaml
firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    # Enable users to SSH in to the servers
    - port: 22
      proto: tcp
      ca_name: user-ca
    - port: any
      proto: icmp
      ca_name: user-ca
```

While your user machines might have this:

```yaml
firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    # Enable TFTP for server machines to collect content
    - port: 69
      proto: udp
      ca_name: server-ca
    - port: any
      proto: icmp
      ca_name: server-ca
```

There is also a ca_sha option, however, this is a bit more tricky to show with
psudocode!

### Statistics and Debugging

If you use Prometheus or Graphite, you might want to consume stats from these
products. Here's the config block for each:

```yaml
stats:
  type: graphite
  prefix: nebula
  protocol: tcp
  host: 127.0.0.1:9999
  interval: 10s
```

```yaml
stats:
  type: prometheus
  listen: 127.0.0.1:8080
  path: /metrics
  namespace: prometheusns
  subsystem: nebula
  interval: 10s
```

In addition, if you're trying to get more debug-style logging (or less log 
data), you can also change your log settings here:

```yaml
logging:
  level: error
```

Your options here are `panic`, `fatal`, `error`, `warning`, `info` or `debug`.

Left alone, it'll return `info` level logs. These logs will, by default, be a
text string. If you want to make that into a json string instead, use this 
block:

```yaml
logging:
  format: json
```
