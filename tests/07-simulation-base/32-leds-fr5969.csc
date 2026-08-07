<?xml version="1.0" encoding="UTF-8"?>
<simconf version="2022112801">
  <simulation>
    <title>LEDs FR5969 Test</title>
    <randomseed>1</randomseed>
    <motedelay_us>1000000</motedelay_us>
    <radiomedium>org.contikios.cooja.radiomediums.SilentRadioMedium</radiomedium>
    <events><logoutput>40000</logoutput></events>
    <motetype>
      org.contikios.cooja.mspmote.MspExp430Fr5969MoteType
      <description>LEDs</description>
      <source>[CONTIKI_DIR]/examples/dev/leds/leds-example.c</source>
      <commands>$(MAKE) -j$(CPUS) leds-example.msp-exp430fr5969 TARGET=msp-exp430fr5969</commands>
      <firmware>[CONTIKI_DIR]/examples/dev/leds/build/msp-exp430fr5969/leds-example.msp-exp430fr5969</firmware>
      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.MoteAttributes</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspClock</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspDefaultSerial</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspExp430Fr5969LED</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspDebugOutput</moteinterface>
      <mote>
        <interface_config>org.contikios.cooja.interfaces.Position<pos x="0.0" y="0.0" /></interface_config>
        <interface_config>org.contikios.cooja.mspmote.interfaces.MspMoteID<id>1</id></interface_config>
      </mote>
    </motetype>
  </simulation>
  <plugin>
    org.contikios.cooja.plugins.LogListener
    <plugin_config><filter /><formatted_time /><coloring /></plugin_config>
    <bounds x="0" y="0" height="400" width="800" z="1" />
  </plugin>
  <plugin>
    org.contikios.cooja.plugins.ScriptRunner
    <plugin_config>
      <script>TIMEOUT(60000);
log.log("Script started\n");
var bootSeen = false;
var transitions = 0;
var lastAny = false;

GENERATE_MSG(45000, "check-leds");

while(true) {
  if (msg != null) {
    log.log("MSG: '" + msg + "'\n");
    if (msg.contains("Starting Contiki-NG")) bootSeen = true;
    if (msg == "check-leds") {
      var anyOn = mote.getInterfaces().getLED().isAnyOn() ||
                  mote.getInterfaces().getLED().isRedOn() ||
                  mote.getInterfaces().getLED().isGreenOn();
      log.log("LED any-on at 45s: " + anyOn + ", transitions seen=" + transitions + "\n");
      if (bootSeen &amp;&amp; transitions &gt; 0) log.testOK();
      else log.testFailed();
    }
  }
  var anyNow = mote.getInterfaces().getLED().isAnyOn();
  if (anyNow != lastAny) {
    transitions++;
    lastAny = anyNow;
    log.log("LED transition #" + transitions + " any=" + anyNow + "\n");
  }
  YIELD();
}</script>
      <active>true</active>
    </plugin_config>
    <bounds x="0" y="402" height="300" width="800" z="2" />
  </plugin>
</simconf>
