/*
 * Copyright (c) 2021, RISE Research Institutes of Sweden AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * \file
 *   A simple resolver test for Contiki-NG.
 * \author
 *   Nicolas Tsiftes <nicolas.tsiftes@ri.se>
 */

#include "contiki.h"
#include "net/ipv6/uip-nameserver.h"
#include "net/ipv6/uiplib.h"
#include "services/resolv/resolv.h"

/* Log configuration. */
#include "sys/log.h"
#define LOG_MODULE "Resolver Test"
#define LOG_LEVEL LOG_LEVEL_INFO

#ifdef TEST_RESOLVER_CONF_NAMESERVER
#define TEST_RESOLVER_NAMESERVER TEST_RESOLVER_CONF_NAMESERVER
#else
#define TEST_RESOLVER_NAMESERVER "fd00::1"
#endif

#ifdef TEST_RESOLVER_CONF_NAME
#define TEST_RESOLVER_NAME TEST_RESOLVER_CONF_NAME
#else
#define TEST_RESOLVER_NAME "ipv6.google.com"
#endif

#ifdef TEST_RESOLVER_CONF_TIMEOUT
#define TEST_RESOLVER_TIMEOUT TEST_RESOLVER_CONF_TIMEOUT
#else
#define TEST_RESOLVER_TIMEOUT CLOCK_SECOND * 10
#endif

struct lookup {
  const char *domain;
  bool found;
};

static struct lookup lookups[] = {
  {"localhost", false},
  {TEST_RESOLVER_NAME, false}};

PROCESS(test_resolver, "DNS resolver test");
AUTOSTART_PROCESSES(&test_resolver);

static void
check_status(struct lookup *lookup)
{
  uip_ipaddr_t *resolved_addr;
  resolv_status_t status;

  status = resolv_lookup(lookup->domain, &resolved_addr);
  LOG_INFO("Query status: ");
  switch(status) {
  case RESOLV_STATUS_CACHED:
    LOG_INFO_("cached\n");
    lookup->found = true;
    break;
  case RESOLV_STATUS_UNCACHED:
    LOG_INFO_("uncached\n");
    lookup->found = true;
    break;
  case RESOLV_STATUS_EXPIRED:
    LOG_INFO_("expired\n");
    break;
  case RESOLV_STATUS_NOT_FOUND:
    LOG_INFO_("not found\n");
    break;
  case RESOLV_STATUS_RESOLVING:
    LOG_INFO_("still resolving\n");
    break;
  default:
    break;
  }

  if(lookup->found) {
    LOG_INFO("%s resolves to ", lookup->domain);
    LOG_INFO_6ADDR(resolved_addr);
    LOG_INFO_("\n");
  }
}

PROCESS_THREAD(test_resolver, ev, data)
{
  static bool test_ok;
  static struct etimer resolver_timeout;
  uip_ipaddr_t nameserver_addr;
  uip_ipaddr_t *addr;
  int i;

  PROCESS_BEGIN();

  uiplib_ipaddrconv(TEST_RESOLVER_NAMESERVER, &nameserver_addr);
  uip_nameserver_update(&nameserver_addr, UIP_NAMESERVER_INFINITE_LIFETIME);

  LOG_INFO("Adding a nameserver at ");
  LOG_INFO_6ADDR(&nameserver_addr);
  LOG_INFO_("\n");

  addr = uip_nameserver_get(0);
  if(addr == NULL) {
    LOG_ERR("No nameserver found!\n");
  } else {
    LOG_INFO("First querying a nameserver at ");
    LOG_INFO_6ADDR(addr);
    LOG_INFO_("\n");
  }

  etimer_set(&resolver_timeout, TEST_RESOLVER_TIMEOUT);

  for(i = 0; i < sizeof(lookups) / sizeof(lookups[0]); i++) {
    LOG_INFO("Resolving DNS name \"%s\"\n", lookups[i].domain);
    resolv_query(lookups[i].domain);
  }

  for(;;) {
    PROCESS_WAIT_EVENT();

    /* The test fails if the timer is triggered. */
    if(etimer_expired(&resolver_timeout)) {
      test_ok = false;
      break;
    }

    if(ev == resolv_event_found) {
      for(i = 0; i < sizeof(lookups) / sizeof(lookups[0]); i++) {
        if(!lookups[i].found) {
          check_status(&lookups[i]);
        }
      }
    }

    test_ok = true;
    for(i = 0; i < sizeof(lookups) / sizeof(lookups[0]); i++) {
      if(!lookups[i].found) {
        test_ok = false;
      }
    }

    /* All lookups have completed. */
    if(test_ok == true) {
      break;
    }
  }

  LOG_INFO("Test %s\n", test_ok ? "SUCCEEDED" : "FAILED");

  PROCESS_END();
}
