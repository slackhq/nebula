## What is Nebula?
Nebula is a scalable overlay networking tool with a focus on performance, simplicity and security.
It lets you seamlessly connect computers anywhere in the world. Nebula is portable, and runs on Linux, OSX, Windows, iOS, and Android.
It can be used to connect a small number of computers, but is also able to connect tens of thousands of computers.

Nebula incorporates a number of existing concepts like encryption, security groups, certificates,
and tunneling, and each of those individual pieces existed before Nebula in various forms.
What makes Nebula different to existing offerings is that it brings all of these ideas together,
resulting in a sum that is greater than its individual parts.



## Downloading Nebula

Nebula runs on Linux, MacOS, Windows, iOS, and Android.

Visit the [Downloading Nebula](https://www.defined.net/nebula/quick-start/#downloading-nebula) page to find links to Nebula releases and mobile apps.

## Documentation

Learn all about the [Nebula](https://www.defined.net/nebula/introduction/) project.

Check out our [Quick Start](https://www.defined.net/nebula/quick-start/) to dive right in and start building your first Nebula network.

Explore the [Configuration Reference](https://www.defined.net/nebula/config/) for details on Nebula configuration and tuning.

## Nebula Slack discussion

You can join the [NebulaOSS Slack Group](https://join.slack.com/t/nebulaoss/shared_invite/enQtOTA5MDI4NDg3MTg4LTkwY2EwNTI4NzQyMzc0M2ZlODBjNWI3NTY1MzhiOThiMmZlZjVkMTI0NGY4YTMyNjUwMWEyNzNkZTJmYzQxOGU) to connect with the maintainers of Nebula and our user community.

## Building Nebula from source

You'll need to download the [`go`](https://golang.org/dl/) programming language to build Nebula yourself.

Clone the current version of Nebula:
```shell
git clone https://github.com/slackhq/nebula
```
Build Nebula for your current OS:
```shell
make
```

Build Nebula for all available platforms:
```shell
make all
```

To build Nebula for a specific platform (ex, Windows):
```shell
make bin-windows
```

See the [Makefile](Makefile) for more details on build targets

## Credits

Nebula was created at Slack Technologies, Inc by Nate Brown and Ryan Huber, with contributions from Oliver Fross, Alan Lam, Wade Simmons, and Lining Wang.



