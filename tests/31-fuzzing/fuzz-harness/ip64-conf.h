/*
 * Configuration of the IP64 module for the fuzzing harness.
 *
 * The module refuses to build without a driver, an input function and a
 * fallback interface, none of which a campaign uses: the entry points call
 * the translation directly rather than letting a packet reach it through an
 * interface. The null driver discards what it is given, and the Ethernet
 * interface is the one a configuration normally names.
 */
#ifndef IP64_CONF_H_
#define IP64_CONF_H_

#include "ip64/ip64-null-driver.h"
#include "ip64/ip64-eth-interface.h"

#define IP64_CONF_ETH_DRIVER                ip64_null_driver
#define IP64_CONF_INPUT                     ip64_eth_interface_input
#define IP64_CONF_UIP_FALLBACK_INTERFACE    ip64_eth_interface

/* A campaign has no host to lease an address from. */
#define IP64_CONF_DHCP                      0

#endif /* IP64_CONF_H_ */
