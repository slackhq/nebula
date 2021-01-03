# Synology Installation

This was tested on *DSM 6.2.3-25426 Update 2*, but as long as nebula runs on the system, there is no reason why there should be any minimum synology requirement for these scripts to work.

Although the best thing would be a standalone package integrated into synology services, simple startup/shutdown scripts can be used without too much effort. These instructions assume you can SSH into your synology.

## Customize Script

You must modify the four user variables at the top of nebula.sh

* SCRIPT - This is the location of your nebula config.yml you use to start nebula
* SUBNET - Subnet of your lighthouse. Example, if your lighthouse is 10.1.18.1, use 10.1.18.0/24
* PIDFILE - Location for a file that stores the process ID of nebula so we can check if it's already running, and restart it
* LOGFILE - Location of a logfile for debug

## Script Installation

Copy our script over to a familiar startup location and make sure it's executable:

```
sudo cp nebula.sh /usr/local/etc/rc.d/nebula.sh
sudo chmod +x /usr/local/etc/rc.d/nebula.sh
```

You can test the script by running:

```
/usr/local/etc/rc.d/nebula.sh start
/usr/local/etc/rc.d/nebula.sh stop
/usr/local/etc/rc.d/nebula.sh restart
```

## Create a Startup Script

Head over to the web portal of your synology and go to control panel. Scroll down to Task Scheduler.

Click Create->Triggerd Tasks->User-defined scripts

Use the following settings:

```
Task: Nebula Start
User: root
Event: Boot-up
```

Under **Task Settings**, use the following in he **User-defined script** section:

```
/usr/local/etc/rc.d/nebula.sh restart
```

If for some reason this isn't working, you can log the result with:


```
/usr/local/etc/rc.d/nebula.sh restart &> /volume1/nebula/start.log
```

***NOTE*** - We are using Restart on purpose in case we did not cleanly shutdown. Our PID file we use to kill our service will still be running, and our start command will fail, so we purposely kill the script before re-running.

## Create a Shutdown Script

Click Create->Triggerd Tasks->User-defined scripts

Use the following settings:

```
Task: Nebula Stop
User: root
Event: Shutdown
```

Under **Task Settings**, use the following in he **User-defined script** section:

```
/usr/local/etc/rc.d/nebula.sh stop &> /volume1/scripts/nebula/stop.log
```

## Troubleshooting

### Is nebula up and running?

Run and verify that 

```
ifconfig
``` 

shows you an interface with the name `nebula1` being up.

### Synology Unclean Shutdown

If the synology did not properly shutdown, the PID file could be present, and the nebula script will exit. You can always force remove the file, or force re-start nebula with the following command:

```
/usr/local/etc/rc.d/nebula.sh restart
```

### Route Not Present

The script creates an additional route, check to see it's present:

```
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         192.168.1.1     0.0.0.0         UG    0      0        0 eth0
10.1.18.0       0.0.0.0         255.255.255.0   U     0      0        0 nebula1
192.168.1.0     0.0.0.0         255.255.255.0   U     0      0        0 eth0
```

We are expecting to see the route we added to our script file. In the example above, it's **10.1.18.0**.
