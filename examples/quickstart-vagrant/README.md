# Quickstart Guide

This guide is intended to bring up a vagrant environment with 1 lighthouse and
2 generic hosts running Nebula.

## Check and install Go on host

Before you start, check what version of Go you have installed:

```
go version
```

Compare with a minimum version that is listed in the [Makefile](https://github.com/slackhq/nebula/blob/master/Makefile#L1)
(Example for master branch).

If necessary, install or update your Go version.

## Creating the virtualenv for ansible

Within the `quickstart-vagrant/` directory, do the following:

```
# make a virtual environment
virtualenv venv

# get into the virtualenv
source venv/bin/activate

# install ansible
pip install -r requirements.yml
```

## Bringing up the vagrant environment

Plugins that are used for the Vagrant environment is `vagrant-hostmanager` and
`vagrant-cachier`.

Vagrant will install them automatically if it is necessary.


All hosts within the Vagrantfile are brought up with:

`vagrant up`

During the execution of the `vagrant up`, the Nebula will be installed using
the Ansible.

Installation of the Nebula can always be repeated using the command:

`vagrant provision`

## Testing within the vagrant env

Once the `vagrant up` is done, hop onto a vagrant box:

`vagrant ssh generic1.vagrant`

or specifically

`ssh vagrant@<ip-address-in-vagrant-file` (password for the vagrant user on the boxes is `vagrant`)

Some quick tests once the vagrant boxes are up are to ping from `generic1.vagrant` to
`generic2.vagrant` using their respective Nebula ip address.

```
vagrant@generic1:~$ ping 10.168.91.220
PING 10.168.91.220 (10.168.91.220) 56(84) bytes of data.
64 bytes from 10.168.91.220: icmp_seq=1 ttl=64 time=241 ms
64 bytes from 10.168.91.220: icmp_seq=2 ttl=64 time=0.704 ms
```

You can further verify that the allowed Nebula firewall rules work by ssh'ing
from 1 generic box to the other.

`ssh vagrant@<nebula-ip-address>`  (password for the vagrant user on the boxes is `vagrant`)

See `/etc/nebula/config.yml` on a box for firewall rules.

To see full handshakes and hostmaps, change the logging config of `/etc/nebula/config.yml`
on the vagrant boxes from info to debug.

You can watch Nebula logs by running:

```
sudo journalctl -fu nebula
```

Refer to the Nebula src code directory's README for further instructions on
configuring Nebula.

## Troubleshooting

### Is Nebula up and running?

Run and verify that:

```
ifconfig
```

shows you an interface with the name `nebula1` being up.

```
vagrant@generic1:~$ ifconfig nebula1
nebula1: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1300
        inet 10.168.91.210  netmask 255.128.0.0  destination 10.168.91.210
        inet6 fe80::aeaf:b105:e6dc:936c  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 2  bytes 168 (168.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 11  bytes 600 (600.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

### Connectivity

Are you able to ping other boxes on the private Nebula network?

The following are the private Nebula ip addresses of the vagrant env:

```
generic1.vagrant [nebula_ip] 10.168.91.210
generic2.vagrant [nebula_ip] 10.168.91.220
lighthouse1.vagrant [nebula_ip] 10.168.91.230
```

Try pinging generic1.vagrant to and from any other box using its Nebula ip above.

Double check the Nebula firewall rules under /etc/nebula/config.yml to make sure
that connectivity is allowed for your use-case if on a specific port.

```
vagrant@lighthouse1:~$ grep -A21 firewall /etc/nebula/config.yml
firewall:
  conntrack:
    tcp_timeout: 12m
    udp_timeout: 3m
    default_timeout: 10m
    max_connections: 100,000

  inbound:
    - proto: icmp
      port: any
      host: any
    - proto: any
      port: 22
      host: any
    - proto: any
      port: 53
      host: any

  outbound:
    - proto: any
      port: any
      host: any
```
