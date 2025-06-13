#include "contiki.h"
#include "os/net/mac/framer/frame802154.h"
#include "os/net/mac/tsch/tsch.h"
#include "os/net/ipv6/uip-nd6.h"
#include "os/net/ipv6/uipopt.h"
#include "os/net/queuebuf.h"
#include "os/net/nbr-table.h"
#include "os/sys/log-conf.h"
#include "os/sys/energest.h"
#include "os/net/routing/routing.h"
#include "os/services/orchestra/orchestra-conf.h"
#include "os/services/lwm2m/lwm2m-queue-mode-conf.h"

#ifdef PROJECT_CONF_PATH
##### "PROJECT_CONF_PATH": _____________________ == PROJECT_CONF_PATH
#else
##### "PROJECT_CONF_PATH": _____________________ ><
#endif

##### "CONTIKI_VERSION_STRING": ________________ == CONTIKI_VERSION_STRING

/* Frame 802.15.4 Configuration */
#undef FRAME802154_IEEE802154_2003
#undef FRAME802154_IEEE802154_2006
#undef FRAME802154_IEEE802154_2015

##### "FRAME802154_VERSION":___________________ == FRAME802154_VERSION

##### "IEEE802154_PANID":______________________ == IEEE802154_PANID

#if MAC_CONF_WITH_TSCH

/* TSCH Configuration */
##### "TSCH_DEFAULT_HOPPING_SEQUENCE": _________ == TSCH_DEFAULT_HOPPING_SEQUENCE

##### "TSCH_JOIN_HOPPING_SEQUENCE": ____________ == TSCH_JOIN_HOPPING_SEQUENCE

##### "TSCH_EB_PERIOD": _______________________ == TSCH_EB_PERIOD

##### "TSCH_MAX_EB_PERIOD": ___________________ == TSCH_MAX_EB_PERIOD

##### "TSCH_DEFAULT_TIMESLOT_TIMING": _________ == TSCH_DEFAULT_TIMESLOT_TIMING

##### "TSCH_SCHEDULE_DEFAULT_LENGTH": _________ == TSCH_SCHEDULE_DEFAULT_LENGTH

##### "TSCH_KEEPALIVE_TIMEOUT": _______________ == TSCH_KEEPALIVE_TIMEOUT

##### "TSCH_MAX_KEEPALIVE_TIMEOUT": ___________ == TSCH_MAX_KEEPALIVE_TIMEOUT

##### "TSCH_DESYNC_THRESHOLD": ________________ == TSCH_DESYNC_THRESHOLD

##### "TSCH_AUTOSTART": _______________________ == TSCH_AUTOSTART

##### "TSCH_MAX_JOIN_PRIORITY": _______________ == TSCH_MAX_JOIN_PRIORITY

##### "TSCH_JOIN_SECURED_ONLY": _______________ == TSCH_JOIN_SECURED_ONLY

##### "TSCH_JOIN_MY_PANID_ONLY": ______________ == TSCH_JOIN_MY_PANID_ONLY

##### "TSCH_ASSOCIATION_POLL_FREQUENCY": ______ == TSCH_ASSOCIATION_POLL_FREQUENCY

##### "TSCH_MAX_INCOMING_PACKETS": ____________ == TSCH_MAX_INCOMING_PACKETS

##### "TSCH_QUEUE_NUM_PER_NEIGHBOR": __________ == TSCH_QUEUE_NUM_PER_NEIGHBOR

##### "TSCH_QUEUE_MAX_NEIGHBOR_QUEUES": _______ == TSCH_QUEUE_MAX_NEIGHBOR_QUEUES

##### "TSCH_SCHEDULE_MAX_SLOTFRAMES": _________ == TSCH_SCHEDULE_MAX_SLOTFRAMES

##### "TSCH_SCHEDULE_MAX_LINKS": ______________ == TSCH_SCHEDULE_MAX_LINKS

##### "TSCH_WITH_SIXTOP": _____________________ == TSCH_WITH_SIXTOP

##### "TSCH_MAC_MAX_FRAME_RETRIES": ___________ == TSCH_MAC_MAX_FRAME_RETRIES

#else /* MAC_CONF_WITH_TSCH */

/* IEEE 802.15.4 Configuration (non-TSCH) */
##### "IEEE802154_DEFAULT_CHANNEL": ___________ == IEEE802154_DEFAULT_CHANNEL

#endif /*MAC_CONF_WITH_TSCH */

#if ROUTING_CONF_RPL_LITE || ROUTING_CONF_RPL_CLASSIC

/* RPL Routing Configuration */
#undef RPL_MOP_NO_DOWNWARD_ROUTES
#undef RPL_MOP_NON_STORING
#undef RPL_MOP_STORING_NO_MULTICAST
#undef RPL_MOP_STORING_MULTICAST

#undef RPL_OCP_OF0
#undef RPL_OCP_MRHOF

##### "RPL_MOP_DEFAULT": ______________________ == RPL_MOP_DEFAULT

##### "RPL_OF_OCP": ___________________________ == RPL_OF_OCP

##### "RPL_WITH_NON_STORING": _________________ == RPL_WITH_NON_STORING

##### "RPL_SUPPORTED_OFS": ____________________ == RPL_SUPPORTED_OFS

##### "RPL_WITH_MC": __________________________ == RPL_WITH_MC

##### "RPL_DAG_MC": ___________________________ == RPL_DAG_MC

##### "RPL_WITH_DAO_ACK": _____________________ == RPL_WITH_DAO_ACK

##### "RPL_WITH_PROBING": _____________________ == RPL_WITH_PROBING

##### "RPL_DEFAULT_LEAF_ONLY": ________________ == RPL_DEFAULT_LEAF_ONLY

##### "RPL_DIO_INTERVAL_MIN": _________________ == RPL_DIO_INTERVAL_MIN

##### "RPL_DIO_INTERVAL_DOUBLINGS": ___________ == RPL_DIO_INTERVAL_DOUBLINGS

##### "RPL_DIO_REDUNDANCY": ___________________ == RPL_DIO_REDUNDANCY

##### "RPL_DEFAULT_LIFETIME_UNIT": ____________ == RPL_DEFAULT_LIFETIME_UNIT

##### "RPL_DEFAULT_LIFETIME": _________________ == RPL_DEFAULT_LIFETIME

##### "RPL_PROBING_INTERVAL": _________________ == RPL_PROBING_INTERVAL

##### "RPL_DAO_MAX_RETRANSMISSIONS": __________ == RPL_DAO_MAX_RETRANSMISSIONS

##### "RPL_MIN_HOPRANKINC": __________________ == RPL_MIN_HOPRANKINC

##### "RPL_DEFAULT_INSTANCE": _________________ == RPL_DEFAULT_INSTANCE

##### "RPL_PREFERENCE": ______________________ == RPL_PREFERENCE

#endif /* RPL routing */

/* Buffer and Neighbor Table Configuration */
##### "QUEUEBUF_NUM": _________________________ == QUEUEBUF_NUM

##### "NBR_TABLE_MAX_NEIGHBORS": ______________ == NBR_TABLE_MAX_NEIGHBORS

##### "NETSTACK_MAX_ROUTE_ENTRIES": ____________ == NETSTACK_MAX_ROUTE_ENTRIES

/* IPv6/uIP Configuration */
##### "UIP_CONF_BUFFER_SIZE": __________________ == UIP_CONF_BUFFER_SIZE
##### "UIP_CONF_UDP": __________________________ == UIP_CONF_UDP

##### "UIP_UDP_CONNS": _______________________ == UIP_UDP_CONNS

##### "UIP_CONF_TCP": __________________________ == UIP_CONF_TCP

##### "UIP_TCP_CONNS": _______________________ == UIP_TCP_CONNS

##### "UIP_ND6_SEND_RA": ______________________ == UIP_ND6_SEND_RA

##### "UIP_ND6_SEND_NS": ______________________ == UIP_ND6_SEND_NS

##### "UIP_ND6_SEND_NA": ______________________ == UIP_ND6_SEND_NA

##### "UIP_ND6_AUTOFILL_NBR_CACHE": ___________ == UIP_ND6_AUTOFILL_NBR_CACHE

/* IPv6 Data Structures Configuration */
##### "UIP_DS6_DEFRT_NBU": ___________________ == UIP_DS6_DEFRT_NBU

##### "UIP_DS6_PREFIX_NBU": __________________ == UIP_DS6_PREFIX_NBU

##### "UIP_DS6_ROUTE_NBU": ___________________ == UIP_DS6_ROUTE_NBU

##### "UIP_DS6_ADDR_NBU": ____________________ == UIP_DS6_ADDR_NBU

##### "UIP_DS6_MADDR_NBU": ___________________ == UIP_DS6_MADDR_NBU

##### "UIP_DS6_AADDR_NBU": ___________________ == UIP_DS6_AADDR_NBU

/* 6LoWPAN Configuration */
##### "SICSLOWPAN_CONF_FRAG": __________________ == SICSLOWPAN_CONF_FRAG

##### "SICSLOWPAN_COMPRESSION": _______________ == SICSLOWPAN_COMPRESSION

/* System Configuration */
##### "ENERGEST_CONF_ON": ______________________ == ENERGEST_CONF_ON

/* Logging Configuration */
##### "LOG_CONF_LEVEL_RPL": ____________________ == LOG_CONF_LEVEL_RPL
##### "LOG_CONF_LEVEL_TCPIP": __________________ == LOG_CONF_LEVEL_TCPIP
##### "LOG_CONF_LEVEL_IPV6": ___________________ == LOG_CONF_LEVEL_IPV6
##### "LOG_CONF_LEVEL_6LOWPAN": ________________ == LOG_CONF_LEVEL_6LOWPAN
##### "LOG_CONF_LEVEL_NULLNET": ________________ == LOG_CONF_LEVEL_NULLNET
##### "LOG_CONF_LEVEL_MAC": ____________________ == LOG_CONF_LEVEL_MAC
##### "LOG_CONF_LEVEL_FRAMER": _________________ == LOG_CONF_LEVEL_FRAMER
##### "LOG_CONF_LEVEL_6TOP": ___________________ == LOG_CONF_LEVEL_6TOP
##### "LOG_CONF_LEVEL_COAP": ___________________ == LOG_CONF_LEVEL_COAP
##### "LOG_CONF_LEVEL_DTLS": ___________________ == LOG_CONF_LEVEL_DTLS
##### "LOG_CONF_LEVEL_SNMP": ___________________ == LOG_CONF_LEVEL_SNMP
##### "LOG_CONF_LEVEL_LWM2M": __________________ == LOG_CONF_LEVEL_LWM2M
##### "LOG_CONF_LEVEL_SYS": ____________________ == LOG_CONF_LEVEL_SYS
##### "LOG_CONF_LEVEL_MAIN": ___________________ == LOG_CONF_LEVEL_MAIN

/* Link Layer Security Configuration */
##### "LLSEC802154_ENABLED": __________________ == LLSEC802154_ENABLED

##### "LLSEC802154_USES_EXPLICIT_KEYS": _______ == LLSEC802154_USES_EXPLICIT_KEYS

##### "LLSEC802154_USES_AUX_HEADER": __________ == LLSEC802154_USES_AUX_HEADER

##### "LLSEC802154_USES_FRAME_COUNTER": _______ == LLSEC802154_USES_FRAME_COUNTER

/* Application Layer Services Configuration */
##### "LWM2M_QUEUE_MODE_ENABLED": _____________ == LWM2M_QUEUE_MODE_ENABLED

##### "LWM2M_QUEUE_MODE_DEFAULT_CLIENT_SLEEP_TIME": == LWM2M_QUEUE_MODE_DEFAULT_CLIENT_SLEEP_TIME

##### "LWM2M_QUEUE_MODE_DEFAULT_CLIENT_AWAKE_TIME": == LWM2M_QUEUE_MODE_DEFAULT_CLIENT_AWAKE_TIME

##### "ORCHESTRA_EBSF_PERIOD": ________________ == ORCHESTRA_EBSF_PERIOD

##### "ORCHESTRA_COMMON_SHARED_PERIOD": _______ == ORCHESTRA_COMMON_SHARED_PERIOD

##### "ORCHESTRA_UNICAST_PERIOD": ____________ == ORCHESTRA_UNICAST_PERIOD

##### "ORCHESTRA_UNICAST_SENDER_BASED": _______ == ORCHESTRA_UNICAST_SENDER_BASED

/* Timer Configuration */
##### "CLOCK_SECOND": ________________________ == CLOCK_SECOND

##### "RTIMER_SECOND": _______________________ == RTIMER_SECOND
