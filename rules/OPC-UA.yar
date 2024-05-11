rule browse_request_forward : OPC_UA
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "OPC UA Browse Broadcast with subtypes"
    uuid = "8d57814a742e428cb4c4a52a093cde72" 
  strings:
    $opc_ua_header = { 4d 53 47 }
    $browse_request_header = { 02 00 00 }
    $browse_direction_forward = { 00 00 00 00 }
    $browse_subtypes = { 01 }
    $node_class_mask = { 00 00 00 00 }
  condition:
    $opc_ua_header at 0 and $browse_request_header at 28 and $browse_direction_forward at 91 and $browse_subtypes at 97 and $node_class_mask at 98
}

rule request_session_python_client : OPC_UA
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Python client request a session"
    uuid = "5acd84d20d144a3cba75165a02035a88" 
  strings:
    $opc_ua_header = { 4d 53 47 }
    $python_client = "Pure Python Client"
    $application_uri = "urn:freeopcua:client"
    $product_uri = "urn:freeopcua.github.no:client"
  condition:
    $opc_ua_header at 0 and $python_client and $product_uri and $application_uri
}

rule request_session_dotnet_client : OPC_UA
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Python client request a session"
    uuid = "5acd84d20d144a3cba75165a02035a88" 
  strings:
    $opc_ua_header = { 4d 53 47 }
    $urn = "urn:"
    $product_uri = "opcfoundation.org/UASDK"
  condition:
    $opc_ua_header at 0 and $product_uri and $urn
}



rule request_session_eclipse_milo_client : OPC_UA
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Milo client request a session"
    uuid = "5acd84d20d144a3cba75165a02035a88" 
  strings:
    $opc_ua_header = { 4d 53 47 }
    $python_client = "Milo Client"
    $application_uri = "urn:eclipse:milo"
    $product_uri = "projects.eclipse.org/projects/iot.milo"
  condition:
    $opc_ua_header at 0 and $python_client and $product_uri and $application_uri
}

rule request_session_nodejs_client : OPC_UA
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Node.js client request a session"
    uuid = "5acd84d20d144a3cba75165a02035a88" 
  strings:
    $opc_ua_header = { 4d 53 47 }
    $urn = "urn:"
    $node_opcua_uri = ":NodeOPCUA-Client"
  condition:
    $opc_ua_header at 0 and $urn and $node_opcua_uri
}

rule request_session_without_cert : OPC_UA
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "A client request a session without certificate"
    uuid = "" 
  strings:
    $opc_ua_header = { 4d 53 47 }
    $certificate = { FF FF FF FF }
  condition:
    $opc_ua_header at 0 and $certificate at 259
}

rule localhost_client : OPC_UA
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "A client creates request access from localhost"
    uuid = "" 
  strings:
    $opc_ua_header = { 4d 53 47 }
    $opc_uri = "opc.tcp://127.0.0.1"
  condition:
    $opc_ua_header at 0 and $opc_uri at 162 
}

rule client_from_internet : OPC_UA
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "A client creates request access from internet"
    uuid = "" 
  strings:
    $opc_ua_header = { 4d 53 47 }
    $protocol = "opc.tcp://"
    $ip = /[0-9]{1,3}\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/
    $private_ip = /(10\.)|(172\.1[6-9])|(172\.2[0-9])|(172\.3[0-1])|(192\.168)/
  condition:
    $opc_ua_header at 0 and $protocol at 162 and $ip at 172 and not $private_ip at 172
}















