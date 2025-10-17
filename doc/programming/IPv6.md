# IPv6

One of the main features of Contiki-NG is a resource-efficient IPv6 network stack designed for lossy and low-power networks. The network stack comprises protocols such as IPv6, TCP, UDP, DNS, RPL, CoAP, LWM2M, and Websockets. Beneath the IPv6 stack, Contiki-NG supports IEEE 802.15.4 wireless communication with Time-Slotted Channel Hopping (TSCH).

## Core IPv6 Stack Documentation

* [IPv6 Core (uIP Stack)](/doc/programming/IPv6-core) - IPv6 packet processing, address management, and stack architecture
* [ICMPv6](/doc/programming/ICMPv6) - Internet Control Message Protocol for IPv6 (ping, errors, messaging)
* [IPv6 Neighbor Discovery](/doc/programming/IPv6-neighbor-discovery) - Address resolution, router discovery, and neighbor management

## Higher-Layer Protocols

* [The RPL routing protocol](/doc/programming/RPL)
* [IPv6 multicast](/doc/programming/IPv6-multicast)
* [CoAP and CoAPs](/doc/programming/CoAP)
* [OMA LWM2M](/doc/programming/LWM2M)

## Link Layer and Scheduling

* [TSCH and 6TiSCH](/doc/programming/TSCH-and-6TiSCH)
* [6TiSCH 6top sublayer](/doc/programming/6TiSCH-6top-sub-layer)
* [6TiSCH scheduler Orchestra](/doc/programming/Orchestra)

## Additional Resources

* [Packet buffers documentation](/doc/programming/Packet-buffers)
* [Memory management](/doc/programming/Memory-management)
