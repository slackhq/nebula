# Don't merge me

# Accessing IPv4-only UnsafeNetworks via an IPv6-only overlay

## Background
Nebula is an VPN-like connectivity solution. It provides what we call an "overlay network", 
an additional IP-addressed network on top of one-or-more traditional "underlay networks". 
As long as two devices with Nebula certificates (credentials, essentially signed keypairs with metadata) can find each other
and exchange traffic via a common underlay network (often this is the Internet), 
they will also be able to exchange traffic securely via a point-to-point, encrypted, authenticated tunnel.

Typically, all Nebula traffic is strongly associated with the Nebula certificate of the sender
(that is, the source IP of all packets matches the IP listed in the sender's certificate).
However, it is useful to be able to  bend this rule. That is why there is another field in the Nebula certificate, named UnsafeNetworks,
which lists the network prefixes that the host bearing this certificate is allowed to "speak for".

## Problem Statement
We want IPv6-only overlay networks to be able to carry IPv4 traffic to reach off-overlay hosts via UnsafeNetworks

### Scenario

To illustrate this scenario, we will define 3 hosts:
* a Phone, running Nebula, assigned the overlay IP fd01::AA/64. It has an undefined underlay, but we assert that it always has working IPv4 OR IPv6 connectivity to Router.
* a Router, running Nebula, assigned the overlay IP fd01::55/64. It has a stable underlay link that Phone can always reach.
* a Printer, which cannot run Nebula, and is only capable of IPv4 communication. It has a direct link to Router, but the Phone cannot reach it directly.

You, the User, wish to use your Phone to print out something on the Printer while you're away from home. How can we make this possible with your IPv6-only Nebula overlay?
In particular, your Phone may connect to any cellular or public WiFi network, and we cannot control the IP address it will be assigned. If you MUST print, an IP conflict is not acceptable. 
Therefore, we cannot simply dismiss this problem by suggesting that you assign a small IPv4 network within your overlay. Sure, it probably works, and in this toy scenario, the odds of a conflict are pretty small. But it scales very poorly. What if a whole company needs to use this printer (or perhaps a less contrived need?)
We can do better.

## Solution

* Even though Phone and Router lack IPv4 assignments, we can still put V4 addresses on their tun devices.
* Each overlay host who wishes to use this feature shall select (or configure?) an assignment within 169.254.0.0/16, the IPv4 link-local range
  * this is a pretty small space, but it confines the region of IP conflict to a much smaller domain. And, because overlay hosts will never dial one another with this address, cryptographic verification of it via the certificate is less important.
  * On Phone, Nebula will configure an unsafe_route to the Printer using this address. Because it is a device route, we do not need to tell the operating system the address of the next hop (no `via`)
  * On Router, Nebula will use this address to masquerade packets from Phone. You'll see!
* Let's walk through setting up a TCP session between Phone and Printer in this scheme:
  * Phone sends SYN to the printer's underlay IPv4 address
  * This packet lands on Phone's Nebula tun device
  * Nebula locates Router as the destination for this packet, as defined in `tun.unsafe_routes`
  * Nebula checks the packet against the outbound chain:
    * the destination IP of Printer is listed in Router's UnsafeNetworks, so that check will pass
    * Phone's source IP is not listed in any certificate, but because the destination address is of `NetworkTypeUnsafe` and this is an outgoing flow, we keep going
    * Actual outbound firewall rules get checked, assume they pass
    * conntrack entry created to permit replies
  * Phone encrypts the packet and sends it to Router
  * Router gets the packet from Phone, and decrypts it. It is passed to the Nebula firewall for evaluation:
    * `firewall.Drop()` on the Router's Nebula inbound rules:
    * Because Router is configured to allow SNAT, and this packet is an IPv4 packet from a IPv6-only host, the firewall module enters "snat mode" (`TODO explain?`)
    * This is a new flow, so the conntrack lookup for it fails
    * `firewall.identifyNetworkType()`
      * identify what "kind" of remote address (this is the inbound firewall, so the remote address is the packet's src IP) we've been given
      * `NetworkTypeVPN`, for example is a remote address that matches the peer's certificate
      * In this case, because the traffic is IPv4 traffic flowing from an IPv6-only host, and we've opted into supporting SNAT, this traffic is marked as `NetworkTypeUncheckedSNATPeer`
    * `firewall.allowNetworkType()` will allow `NetworkTypeUncheckedSNATPeer` traffic to proceed because we have opted into SNAT
    * `firewall.willingToHandleLocalAddr()` now needs to check if we're willing to accept the destination address
      * Because this traffic is addressed to a destination listed in our UnsafeNetworks, it's considered "routable" and passes this check
    * Nebula's firewall rules are evaluated as normal. In particular, the `cidr` parameter will be checked against the IPv4 address, NOT the IPv6 address in the Phone's certificate
      * @Nate I think this is "correct", but could be a source of footgun
    * Let's assume the Nebula rules accept the traffic
    * We create a conntrack entry for this flow
    * We do not want to transmit with the IPv4 source IP we got from Phone. We don't want the Phone's IP assignments (in this scheme) to enter the network-space on Router at all.
    * To this end, we rewrite the source address (and port, if needed) to our own pre-selected IPv4 link-local address. This address will never actually leave the machine, but we need it so return traffic can be routed back to the nebula tun on Router
      * Replace source IP with "Router's SNAT address"
      * Look in our conntrack table, and ensure we do not already have a flow that matches this srcip/srcport/dstip/dstport/proto tuple
        * if we do, increment srcport until we find an empty slot. Only use ephemeral ports. This gives 0x7ff flows per dstip/dstport/proto tuple, which ought to be plenty.
        * Record the original srcip/srcport as part of the conntrack data for later
      * Fix checksums
    * Nebula writes the rewritten packet to Router's tun
    * netfilter picks up the packet. In this example, Router is using `iptables`. A rule in the `nat` table similar to `-A POSTROUTING -d PRINTER_UNDERLAY_IP_HERE/32 -j MASQUERADE` is hit
    * This ensures that "Router's SNAT address" never actually leaves Router.
    * The packet leaves Router, and hits Printer
    * Printer gleefully accepts the SYN from Router, and replies with an ACK
    * iptables on Router de-masquerades the packet, and delivers it to the Nebula tun
    * Nebula reads the packet off the tun. Because it came from the tun, and not UDP, remember that this is considered "inside" traffic and will be evaluated as "outbound" traffic by Nebula.
    * Because this is inside traffic, it needs to be associated with a HostInfo before we can pass it to the firewall.
      * Check that the packet is addressed to the "Router's SNAT address". If so, attempt to un-SNAT by "peeking" into conntrack
        * If a Router needs to speak to _another_ Router with v4-in-v6 unsafe_routes like this, it _must_ use a distinct address from the "Router's SNAT address"
          * the easy way on Linux to assure this is to set a route for the "Router SNAT address" to the Nebula tun, but not actually assign the address
      * The "peek" into conntrack succeeds, and we find everything we need to rewrite the packet for transmission to Phone, as well as Phone's overlay IP, which lets us locate Phone's HostInfo
        * The packet is rewritten, replacing the destination address/port to match the ones Phone expects
        * checksums corrected
      * Check the Nebula firewall, and see that we have a valid conntrack entry (wow!)
        * we could _technically_ skip this check, but I dislike not passing all traffic we intend to accept into `firewall.Drop()`. The second conntrack locking-lookup does suck. There's room for improvement here.
      * The traffic is accepted, encrypted, and sent back to Phone
  * Phone gets the packet from Router, decrypts it, checks the firewall
    * we have a conntrack entry for this flow, so the firewall accepts it, and delivers it to the tun
  * Both sides now have a nice conntrack entry, and traffic should continue to flow uninterrupted until it expires

This conntrack entry technically creates a risk though. Let's examine that.
The Phone will accept inbound traffic matching the conntrack spec from any Router-like host authorized to speak for that UnsafeRoute, not just Router. In theory, this is desireable, and the risk is mitigated by accepting/trusting Nebula's certificate model.
There's a good chance that if you "switch" from one Router to another, you'll lose your session on your Printer-like host. Such is life under NAT!

Can the Router be exploited somehow?
* an attacker that shares a network with Printer would be able to spoof traffic as if they are Printer. This is the same risk as UnsafeNetworks today.
* an attacker on the overlay would have their traffic evaluated as inbound
  * if they try to tx on the same source IP as Phone, SNAT will assign a different port
  * if they try to send inbound traffic that matches the un-masqueraded traffic iptables would have delivered
    * conntrack will accept the packet, but before we finish firewalling and return, is the applySnat step
    * this will fail because the hostinfo that sent the packet does not contain the vpnip that is associated with the snat entry