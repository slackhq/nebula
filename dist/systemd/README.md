# Using Nebula with Systemd

This guide describes how to use Systemd to manage one or multiple Nebula services.

## Install the unit files 

Copy the units files in your distribution's service directory.

```sh
cp dist/systemd/*.service /etc/systemd/system/
```

## Create a new network

```sh
mkdir /etc/nebula/mynet
cd /etc/nebula/mynet
nebula-cert ca -name "mynet"
nebula-cert sign -name "lighthouse" -out-key /etc/nebula/mynet/host.key -out-crt /etc/nebula/mynet/host.crt -ip "10.200.0.1/24"
wget https://raw.githubusercontent.com/slackhq/nebula/master/examples/config.yml
<edit the config to your needs>
```

#### REMINDER

You should probably move your ca.key away from the lighthouse or any nebula host.

## Enable the service

```sh
systemctl enable nebula@mynet
systemctl start nebula@mynet 
```