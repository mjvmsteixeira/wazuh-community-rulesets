<group name="sliver,">
  <!-- Rule for detecting potential sliver shell execution -->
  <rule id="107000" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.parentImage" type="pcre2">.exe</field>
    <field name="win.eventdata.image" type="pcre2">powershell.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2"> -NoExit -Command \[Console\]::OutputEncoding=\[Text.UTF8Encoding]::UTF8</field>
    <description>Possible Sliver C2 activity: shell executed: $(win.eventdata.commandLine).</description>
    <mitre>
      <id>T1086</id>
    </mitre>
  </rule>

  <!-- Rule for detecting potential process injection -->
  <rule id="107001" level="9">
    <if_sid>61610</if_sid>
    <field name="win.eventdata.sourceImage" type="pcre2">.exe</field>
    <field name="win.eventdata.targetImage" type="pcre2">C:\\\\Program\ Files\\\\D*[A-Za-z0-9_.]*\\\\[A-Za-z0-9_.]*\\\\[A-Za-z0-9_.]*\\\\[A-Za-z0-9_.]*.exe$</field>
    <description>Suspicious process injection activity detected from $(win.eventdata.sourceImage) on $(win.eventdata.targetImage).</description>
    <mitre>
      <id>T1055</id>
    </mitre>
  </rule>
</group>
