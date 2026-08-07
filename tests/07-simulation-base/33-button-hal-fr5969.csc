<?xml version="1.0" encoding="UTF-8"?>
<simconf version="2022112801">
  <simulation>
    <title>Button HAL FR5969 Test</title>
    <randomseed>1</randomseed>
    <motedelay_us>1000000</motedelay_us>
    <radiomedium>org.contikios.cooja.radiomediums.SilentRadioMedium</radiomedium>
    <events><logoutput>40000</logoutput></events>
    <motetype>
      org.contikios.cooja.mspmote.MspExp430Fr5969MoteType
      <description>Button HAL</description>
      <source>[CONTIKI_DIR]/examples/dev/button-hal/button-hal-example.c</source>
      <commands>$(MAKE) -j$(CPUS) button-hal-example.msp-exp430fr5969 TARGET=msp-exp430fr5969</commands>
      <firmware>[CONTIKI_DIR]/examples/dev/button-hal/build/msp-exp430fr5969/button-hal-example.msp-exp430fr5969</firmware>
      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.MoteAttributes</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspClock</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspButton</moteinterface>
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
      <script>TIMEOUT(30000);
log.log("Script started\n");
var pressSeen = false;
var releaseSeen = false;

GENERATE_MSG(3000, "press");
GENERATE_MSG(3500, "release");

while(true) {
  log.log("MSG: '" + msg + "'\n");
  if (msg == "press") {
    log.log("[script] pressButton()\n");
    mote.getInterfaces().getButton().pressButton();
  }
  if (msg == "release") {
    log.log("[script] releaseButton()\n");
    mote.getInterfaces().getButton().releaseButton();
  }
  if (msg.contains("Press event")) pressSeen = true;
  if (msg.contains("Release event")) releaseSeen = true;
  if (pressSeen &amp;&amp; releaseSeen) log.testOK();
  YIELD();
}</script>
      <active>true</active>
    </plugin_config>
    <bounds x="0" y="402" height="300" width="800" z="2" />
  </plugin>
</simconf>
