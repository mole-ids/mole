rule unavaliability : MTCONNECT
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "The adapter is unavaliable"
    uuid = "a0a0a53ea3b540f6ba17751c007c52fb"
  strings:
    $http_header = "HTTP"
    $xml_schema_loc = "urn:mtconnect.org:MTConnectStreams"
    $xml_devicestream_tag = "<DeviceStream"
    $xml_componentstreams_tag = "<ComponentStreams"
    $xml_events_tag = "<Events>"
    $xml_state_tag = "UNAVAILABLE</Availability>"
  condition:
    $http_header at 0 and $xml_schema_loc and $xml_devicestream_tag and $xml_componentstreams_tag and $xml_events_tag and $xml_state_tag 
}

rule armed_emergency_stop : MTCONNECT
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "Emergency stop detected."
    uuid = "86e6519170924b118c78b75a34bb4aa6"
  strings:
    $http_header = "HTTP"
    $xml_schema_loc = "urn:mtconnect.org:MTConnectStreams"
    $xml_devicestream_tag = "<DeviceStream"
    $xml_componentstreams_tag = "<ComponentStreams"
    $xml_events_tag = "<Events>"
    $xml_state_tag = "ARMED</EmergencyStop>"
  condition: 
    $http_header at 0 and $xml_schema_loc and $xml_devicestream_tag and $xml_componentstreams_tag and $xml_events_tag and $xml_state_tag 
}

rule triggered_emergency_stop : MTCONNECT
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "End of emergency stop detected."
    uuid = "86e6519170924b118c78b75a34bb4aa6"
  strings:
    $http_header = "HTTP"
    $xml_schema_loc = "urn:mtconnect.org:MTConnectStreams"
    $xml_devicestream_tag = "<DeviceStream"
    $xml_componentstreams_tag = "<ComponentStreams"
    $xml_events_tag = "<Events>"
    $xml_state_tag = "TRIGGERED</EmergencyStop>"
  condition: 
    $http_header at 0 and $xml_schema_loc and $xml_devicestream_tag and $xml_componentstreams_tag and $xml_events_tag and $xml_state_tag 
}

rule interface_state : MTCONNECT
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "The interface state is disabled."
    uuid = "9d51215f72444b8db9c698e3b9202453"
  strings:
    $http_header = "HTTP"
    $xml_schema_loc = "urn:mtconnect.org:MTConnectStreams"
    $xml_devicestream_tag = "<DeviceStream"
    $xml_componentstreams_tag = "<ComponentStreams"
    $xml_events_tag = "<Events>"
    $xml_state_tag = "DISABLED</InterfaceState>"
  condition: 
    $http_header at 0 and $xml_schema_loc and $xml_devicestream_tag and $xml_componentstreams_tag and $xml_events_tag and $xml_state_tag 
}

rule power_state_off : MTCONNECT
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "The adapter is powered off."
    uuid = "f7ecc7d8660e4ebba7630be19cffab0f"
  strings:
    $http_header = "HTTP"
    $xml_schema_loc = "urn:mtconnect.org:MTConnectStreams"
    $xml_devicestream_tag = "<DeviceStream"
    $xml_componentstreams_tag = "<ComponentStreams"
    $xml_events_tag = "<Events>"
    $xml_state_tag = "OFF</PowerState>"
  condition: 
    $http_header at 0 and $xml_schema_loc and $xml_devicestream_tag and $xml_componentstreams_tag and $xml_events_tag and $xml_state_tag 
}

rule program_edit_active : MTCONNECT
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "The controller is in the program edit mode."
    uuid = "b7950c6128784cd9a37d93ab00c91a2b"
  strings:
    $http_header = "HTTP"
    $xml_schema_loc = "urn:mtconnect.org:MTConnectStreams"
    $xml_devicestream_tag = "<DeviceStream"
    $xml_componentstreams_tag = "<ComponentStreams"
    $xml_events_tag = "<Events>"
    $xml_state_tag = "ACTIVE</ProgramEdit>"
  condition: 
    $http_header at 0 and $xml_schema_loc and $xml_devicestream_tag and $xml_componentstreams_tag and $xml_events_tag and $xml_state_tag 
}

rule development_functional_mode : MTCONNECT
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "The functional mode is development."
    uuid = "c9e8a7c6a018423ca29cdac13afbf36b"
  strings:
    $http_header = "HTTP"
    $xml_schema_loc = "urn:mtconnect.org:MTConnectStreams"
    $xml_devicestream_tag = "<DeviceStream"
    $xml_componentstreams_tag = "<ComponentStreams"
    $xml_events_tag = "<Events>"
    $xml_state_tag = "PROCESS_DEVELOPMENT</FunctionalMode>"
  condition: 
    $http_header at 0 and $xml_schema_loc and $xml_devicestream_tag and $xml_componentstreams_tag and $xml_events_tag and $xml_state_tag 
}

rule maintenance_functional_mode : MTCONNECT
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "The functional mode is maintenance."
    uuid = "26159ec625064a1681a30cd6c8130ef0"
  strings:
    $http_header = "HTTP"
    $xml_schema_loc = "urn:mtconnect.org:MTConnectStreams"
    $xml_devicestream_tag = "<DeviceStream"
    $xml_componentstreams_tag = "<ComponentStreams"
    $xml_events_tag = "<Events>"
    $xml_state_tag = "MAINTENANCE</FunctionalMode>"
  condition: 
    $http_header at 0 and $xml_schema_loc and $xml_devicestream_tag and $xml_componentstreams_tag and $xml_events_tag and $xml_state_tag 
}

