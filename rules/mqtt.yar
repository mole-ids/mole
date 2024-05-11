rule connection_response_unacceptable_protocol_version : mqtt
{
  meta:
    author = "Luis J. Cuervo <lcuervo@barbaraiot.com>"
    description = "Connection - Unaceptable protocol version"
    uuid = "2bd8b42b71004657aa3e36c97006559a"
  strings: 
    $conn = { 20 }
    $response = { 01 }
  condition: 
    $conn at 0 and $response at 3
}

rule connection_response_identifier_rejected : mqtt
{
  meta:
    author = "Luis J. Cuervo <lcuervo@barbaraiot.com>"
    description = "Connection - Identifier rejected"
    uuid = "0e917a82cac14f6297f750cc78609499"
  strings:
    $conn = { 20 }
    $response = { 02 }
  condition:
    $conn at 0 and $response at 3
}

rule connection_response_bad_username_password : mqtt
{
  meta:
    author = "Luis J. Cuervo <lcuervo@barbaraiot.com>"
    description = "Connection - Bad username or password"
    uuid = "e3b8d3df41c74e6eb390b4cf8b9b9893"
  strings:
    $conn = { 20 }
    $response = { 04 }
  condition:
    $conn at 0 and $response at 3
}

rule connection_response_not_authorized : mqtt
{
  meta:
    author = "Luis J. Cuervo <lcuervo@barbaraiot.com>"
    description = "Connection - Not authorized"
    uuid = "79cbd7e069964869a44db63acdc42e3b"
  strings:
    $conn = { 20 }
    $response = { 05 }
  condition:
    $conn at 0 and $response at 3
}

rule connection_unknown_protocol_name : mqtt
{
  meta:
    author = "Luis J. Cuervo <lcuervo@barbaraiot.com>"
    description = "Connection - Unknown protocol name"
    uuid = "d78254de6cb14cbdbe6d095d26b4d981"
  strings:
    $conn = { 10 }
    $MQTT = { 4D515454 }
    $MQIsdp = { 4D5149736470 }
  condition:
    $conn at 0 and (not $MQTT at 4) and (not $MQIsdp at 4)
}
