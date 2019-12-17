## 什么是 Nebula?
Nebula是一种可扩展的覆盖网络工具，专注于性能，简单性和安全性。
它使您可以无缝连接世界各地的计算机。 Nebula是便携式的，并且可以在Linux，OSX和Windows上运行。
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

## 快速上手
你需要以下内容来配置 nebula。

#### 1. Nebula 在您平台的[二进制文件](https://github.com/slackhq/nebula/releases)。 具体来说，您需要为每个使用的平台提供 ``nebula-cert`` 和特定的 ``nebula`` 二进制文件。

#### 2. (选择性, 但是你真的应该准备..) 至少一个 发现节点 和一个可路由的IP地址。(称为: lighthouse[灯塔])

Nebula 的 发现节点(lighthouse) 允许各个节点互相发现。 一个发现节点是唯一一个IP地址应该不变的节点。一个发现节点需要非常少的资源，你可以使用最便宜的VPS在某个云平台上。
当你启动你的服务器，确保 nebula的端口(默认 UDP/4242) 是通的。

#### 3. 一个 nebula 的授权证书。这是整个nebula网络的根证书。
  执行以下命令来创建一个ca证书

  ```
  ./nebula-cert ca -name "Myorganization, Inc"
  ```
  这个命令将会创建名为 `ca.key` 和 `ca.cert` 的秘钥以及证书文件在当前目录。`ca.key`文件是您将创建的最敏感的文件，因为您将使用此文件去给其他nebula网络的节点签发证书。请将此文件存储在安全的地方，最好使用强加密。
#### 4. 使用根证书生成的 Nebula 节点秘钥和证书 
假设您有四个节点，它们名为: lighthouse1, laptop, server1, host3。 你可以随心所欲地使用任何名字，包括 FQDN。 你也需要为每一个节点分配它们的局域网IP地址。在这个例子中，我们创建一个一个 192.168.100.x/24 的 nebula 网络。此示例还演示了 nebula group，以后可将其用于定义 nebula网络 中的流量规则。
```
./nebula-cert sign -name "lighthouse1" -ip "192.168.100.1/24"
./nebula-cert sign -name "laptop" -ip "192.168.100.2/24" -groups "laptop,home,ssh"
./nebula-cert sign -name "server1" -ip "192.168.100.9/24" -groups "servers"
./nebula-cert sign -name "host3" -ip "192.168.100.9/24"
```

#### 5. 配置每个节点的配置文件
下载 [示例配置文件](https://github.com/slackhq/nebula/blob/master/examples/config.yml).

* 在 发现节点(灯塔 lighthouse), 你需要设置 `am_lighthouse: true`.

* 在每一个节点, 确保在灯塔中正确定义了 lighthouse `static_host_map` 部分, 和 添加到 lighthouse 的 `host` 部分。


#### 6. 将nebula证书，配置和二进制文件复制到每个主机

为每一个主机， 复制 nebula 的二进制文件并保证将 #5 的 `config.yaml` 和 #4 的 `ca.crt`, `{host}.crt`, 和 `{host}.key` 文件在同一目录。

**请勿 将发现节点的 `ca.key` 文件复制到任何主机**

#### 7. 启动每个节点的 nebula
```
./nebula -config /path/to/config.yaml
```

## 从源码编译 Nebula

下载 golang 和 clone 此仓库，并进入 nebula 目录。

构建适用于所有平台的 nebula:
`make all`

构建适用于某个平台的 nebula(比如说, Windows):
`make bin-windows`

查看 [Makefile](Makefile) 以获取关于构建目标的更多信息。

## Credits

Nebula was created at Slack Technologies, Inc by Nate Brown and Ryan Huber, with contributions from Oliver Fross, Alan Lam, Wade Simmons, and Lining Wang.




 