#define UIP_CONF_TCP 1

#define UIP_CONF_ND6_SEND_NS 1

#define LOG_CONF_LEVEL_RPL              LOG_LEVEL_INFO

/* Enable detailed flow-control diagnostics so the test trace shows
   the advertised window, retention/drain transitions, and any
   overflow events. */
#define LOG_CONF_LEVEL_TCPIP            LOG_LEVEL_DBG

#ifdef BUFSIZE
#define UIP_CONF_BUFFER_SIZE BUFSIZE
#endif /* BUFSIZE */
