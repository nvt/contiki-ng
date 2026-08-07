<?xml version="1.0" encoding="UTF-8"?>
<simconf version="2022112801">
  <simulation>
    <title>GPIO HAL FR5969 Test</title>
    <randomseed>1</randomseed>
    <motedelay_us>1000000</motedelay_us>
    <radiomedium>
      org.contikios.cooja.radiomediums.SilentRadioMedium
    </radiomedium>
    <events>
      <logoutput>40000</logoutput>
    </events>
    <motetype>
      org.contikios.cooja.mspmote.MspExp430Fr5969MoteType
      <description>GPIO HAL Example</description>
      <source>[CONTIKI_DIR]/examples/dev/gpio-hal/gpio-hal-example.c</source>
      <commands>$(MAKE) -j$(CPUS) gpio-hal-example.msp-exp430fr5969 TARGET=msp-exp430fr5969</commands>
      <firmware>[CONTIKI_DIR]/examples/dev/gpio-hal/build/msp-exp430fr5969/gpio-hal-example.msp-exp430fr5969</firmware>
      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.MoteAttributes</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspClock</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspDefaultSerial</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspExp430Fr5969LED</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspDebugOutput</moteinterface>
      <mote>
        <interface_config>
          org.contikios.cooja.interfaces.Position
          <pos x="0.0" y="0.0" />
        </interface_config>
        <interface_config>
          org.contikios.cooja.mspmote.interfaces.MspMoteID
          <id>1</id>
        </interface_config>
      </mote>
    </motetype>
  </simulation>
  <plugin>
    org.contikios.cooja.plugins.LogListener
    <plugin_config>
      <filter />
      <formatted_time />
      <coloring />
    </plugin_config>
    <bounds x="0" y="0" height="400" width="800" z="1" />
  </plugin>
  <plugin>
    org.contikios.cooja.plugins.ScriptRunner
    <plugin_config>
      <script>TIMEOUT(60000);

log.log("Script started\n");
var high = 0;
var low = 0;

while(true) {
  log.log("MSG: '" + msg + "'\n");
  if (msg.contains("Pins are")) {
    if (msg.contains("1=1, 2=1, 3=1") &amp;&amp; msg.contains("mask=0x00000050")) {
      high++;
    } else if (msg.contains("1=0, 2=0, 3=0") &amp;&amp; msg.contains("mask=0x00000000")) {
      low++;
    } else {
      log.log("unexpected pin read-back: " + msg + "\n");
      log.testFailed();
    }
    if (high &gt;= 2 &amp;&amp; low &gt;= 2) {
      log.testOK();
    }
  }
  YIELD();
}</script>
      <active>true</active>
    </plugin_config>
    <bounds x="0" y="402" height="300" width="800" z="2" />
  </plugin>
</simconf>
