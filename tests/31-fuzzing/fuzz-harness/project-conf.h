/*
 * Configuration for the fuzzing harness.
 *
 * Checksum verification is disabled so that mutated input reaches the
 * parsers instead of being rejected by the checks in uip6.c. Logging is
 * disabled because it dominates the run time of a single injection.
 */
#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define UIP_CONF_IPV6_CHECKS                       0
#define UIP_CONF_UDP_CHECKS                        0

#define LOG_CONF_LEVEL_IPV6                        LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_RPL                         LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_6LOWPAN                     LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_TCPIP                       LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_MAC                         LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_FRAMER                      LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_MAIN                        LOG_LEVEL_NONE

#endif /* PROJECT_CONF_H_ */
