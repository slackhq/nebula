## 什么是 Nebula?
Nebula是一种可扩展的覆盖网络工具，专注于性能，简单性和安全性。
它使您可以无缝连接世界各地的计算机。 Nebula是便携式的，并且可以在Linux，OSX和Windows上运行。
（也：保持安静，但是我们有一个在iOS上运行的早期原型）。
它可以用于连接少量计算机，但也可以连接数万台计算机。

Nebula 结合了许多现代技术，如： 加密，安全组，证书，和连接隧道。而每个单独的技术都以各种形式存在于其他项目。
使 Nebula 与现有产品不同的是，Nebula 将所有这些技术融合在一起。

在[这里](https://medium.com/p/884110a5579)查看更多关于 Nebula 的信息

## 技术概述
Nebula 是一个基于 [Noise Protocol Framework](https://noiseprotocol.org/) 的点对点认证软件。
Nebula 使用证书来分配节点的IP地址，名称和用户定义组内的成员身份。
Nebula的用户定义组允许在节点之间进行提供商不可知的流量过滤。
发现节点允许各个对等方找到彼此，并且可以选择使用UDP打洞来从大多数防火墙或NAT后面建立连接。
用户可以在任意数量的云服务提供商，数据中心和端点的节点之间移动数据，而无需维护特定的寻址方案。

Nebula 在默认配置中使用 ``elliptic curve Diffie-Hellman``秘钥交换，和 ``AES-256-GCM``。

创建 Nebula 的目的是为主机托管组提供安全的通信机制，甚至可以跨网络进行通信，同时启用与云安全组风格相似的表达性防火墙定义。
## Getting started (qui

To set up a Nebula network, you'll need:

#### 1. The [Nebula binaries](https://github.com/slackhq/nebula/releases) for your specific platform. Specifically you'll need `nebula-cert` and the specific nebula binary for each platform you use.

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
./nebula-cert sign -name "host3" -ip "192.168.100.9/24"
```

#### 5. Configuration files for each host
Download a copy of the nebula [example configuration](https://github.com/slackhq/nebula/blob/master/examples/config.yml).

* On the lighthouse node, you'll need to ensure `am_lighthouse: true` is set.

* On the individual hosts, ensure the lighthouse is defined properly in the `static_host_map` section, and is added to the lighthouse `hosts` section.


#### 6. Copy nebula credentials, configuration, and binaries to each host

For each host, copy the nebula binary to the host, along with `config.yaml` from step 5, and the files `ca.crt`, `{host}.crt`, and `{host}.key` from step 4.

**DO NOT COPY `ca.key` TO INDIVIDUAL NODES.**

#### 7. Run nebula on each host
```
./nebula -config /path/to/config.yaml
```

## Building Nebula from source

Download go and clone this repo. Change to the nebula directory.

To build nebula for all platforms:
`make all`

To build nebula for a specific platform (ex, Windows):
`make bin-windows`

See the [Makefile](Makefile) for more details on build targets

## Credits

Nebula was created at Slack Technologies, Inc by Nate Brown and Ryan Huber, with contributions from Oliver Fross, Alan Lam, Wade Simmons, and Lining Wang.




 