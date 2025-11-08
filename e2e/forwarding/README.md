# Userspace port forwarding
A simple speedtest for userspace port forwarding that can run without root access.

## A side
Nebula running at port 10000, forwarding inbound TCP connections on port 5201 to 127.0.0.1:15001.

## B side
Nebula running at port 10001, forwarding outbound TCP connections from 127.0.0.1:15002 to port 5201 of the A side.

## Speedtest

   ┌──────────────────────┐:10001     :10002┌──────────────────────┐
   │    Nebula A side     ├─────────────────┤    Nebula B side     │
   │                      │                 │                      │
   │    192.168.100.1     │    TCP 5201     │    192.168.100.2     │
   │          ┌───────────┼─────────────────┼──────────┐           │
   │          │           ├─────────────────┤          │           │
   └──────────▼───────────┘                 └──────────▲───────────┘
              │                                        │ 127.0.0.1:15002
              │                                        │
   ┌──────────▼───────────┐                 ┌──────────┴───────────┐
   │                      │                 │                      │
   │                      │                 │                      │
   │  iperf3 -s -p 15001  │                 │  iperf3 -c -p 15001  │
   │                      │                 │                      │
   │                      │                 │                      │
   └──────────────────────┘                 └──────────────────────┘
