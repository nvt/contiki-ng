# platform-specific/zoul/orion

This directory holds examples for the Zolertia Orion Ethernet router, based on the Zoul and ENC28J60 modules, with active POE support.

### HTTP client examples


There are available 2 examples ready to use using the `http-socket` library:

* The `client` example just makes a HTTP `GET` request to a know page and retrieves
  the result.

* The `ifttt-client` example sends a HTTP `POST` request to [IFTTT](https://ifttt.com/recipes) whenever the user button is pressed, building an Internet button to connect to several channels and applications, such as `Drive`, `Evernote` and many others.

Both examples reach IPv4 servers through a NAT64 address, and therefore require a border router that provides NAT64 translation.  See [NAT64 for Contiki-NG](/doc/getting-started/NAT64-for-Contiki-NG).

To configure the `IFTTT` demo just edit the `project-conf.h` file and change the name of the event and write your API key:

````
#define IFTTT_EVENT   "button"
#define IFTTT_KEY     "XXXXXX"
````

To compile and flash:

````
cd client
make TARGET=zoul ifttt-client.upload
````

The examples can optionally run on 2.4GHz or with the Sub-1GHz radio interface.  In the `project-conf.h` file you can alternatively enable one or another as follows:

* RF 2.4GHz (cc2538 built-in)

````
#define NETSTACK_CONF_RADIO         cc2538_rf_driver
#define ANTENNA_SW_SELECT_DEF_CONF  ANTENNA_SW_SELECT_2_4GHZ
````

* RF Sub-1GHz (CC1200)

````
#define NETSTACK_CONF_RADIO         cc1200_driver
#define ANTENNA_SW_SELECT_DEF_CONF  ANTENNA_SW_SELECT_SUBGHZ
````

### Note on the removed IP64 router

This directory previously held an `ip64-router` example, built on the on-device IPv4/IP64 translation module (`os/services/ip64`).  That module has been removed, so on-device IPv4 translation is no longer available on this board.  Use a border router with NAT64 instead, as described in [NAT64 for Contiki-NG](/doc/getting-started/NAT64-for-Contiki-NG).
