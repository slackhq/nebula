# Nebula Snap package

This is an atempt at creating a snap package for the Nebula overlay networking tool.

Current state:

* Nebula binary is running in strict confinement. For this to work you will have to provide:
  * `config.yaml in /var/snap/nebula/config`
  * `ca.crt in /var/snap/nebula/certs`
  * `nebula-node.crt and nebula-node.key in /var/snap/nebula/certs`
* CA creation and certificate signing is working. However, the name of the produced certs are hardcoded to:
  * `ca.crt`
  * `ca.key`
  * `nebula-node.crt`
  * `nebula-node.key`
* Since created certs are placed in `/var/snap/nebula` the cert-functionality needs sudo permissions. Not optimal perhaps, but necessary.

## Usage

### Starting Nebula
After placing a config.yaml in `/var/snap/nebula/config` you can either start Nebula manually or use the provided daemon

See [here](https://arstechnica.com/gadgets/2019/12/how-to-set-up-your-own-nebula-mesh-vpn-step-by-step/) for instructions on the config file. Also, the [Nebula github page](https://github.com/slackhq/nebula) is a good resource. An example config.yaml can be found there.

#### Start manually:
`sudo nebula`

You can NOT provide a location for the config.yaml file. It is hardcoded to `/var/snap/nebula/config`

#### Start the daemon:
`sudo snap start nebula.daemon`

:warning: There seems to be an issue with the daemon after a reboot **if the address to the lighthouse is stated as a domain name (e g lighthouse.example.com)**. The daemon is supposed to be started automatically on boot and it gets started. However, Nebula does not get a connection to the lighthouse. A **manual restart of the daemon** fixes this: `sudo snap restart nebula.daemon`
This problem does not, however, occur if the ip of the lighthouse is put into the config file. (See [here](https://github.com/slackhq/nebula/issues/206))

To check if the daemon started as expected:
`sudo snap logs nebula.daemon`

or using systemd:s logging facilities:
`sudo journalctl -r -u snap.nebula.daemon.service`

### Certificate creation

#### Generate a Certificate Authority:

`sudo nebula.cert-ca -name <ORGANIZATION_NAME>`

This will generate `ca.crt` and `ca.key`
Again, paths are hardcoded to `/var/snap/nebula/certs` so NOT possible to change this at the moment.

#### Generate node certificates and sign them with the above created CA key:

`sudo nebula.cert-sign -name <CLIENT_NAME> -ip <CLIENT_IP_ADDRESS>`

This will generate `nebula-node.crt` and `nebula-node.key` placed in `/var/snap/nebula/certs`
