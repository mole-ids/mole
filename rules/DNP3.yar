rule unsolicited_response : DNP3 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "The server reports unsolicited response from client"
    uuid = "4d2d28ec58684736914e7c779f0d528c"
  strings: 
    $dnp3_header = { 05 64 }
    $unsolicited_response = { 82 }
  condition: 
    $dnp3_header at 0 and $unsolicited_response at 12 and #dnp3_header < 2
}


rule cold_restart : DNP3
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Client sending cold restart command"
    uuid = "12010549da5148508a53294062755d5a" 
  strings:
    $dnp3_header = { 05 64 }
    $cold_restart = { 0d }
  condition:
    $dnp3_header at 0 and $cold_restart at 12 and #dnp3_header < 2
}

rule warm_restart : DNP3
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Client sending warm restart command"
    uuid = "8d6a7c77057c48daa3c72001e9f3d689" 
  strings:
    $dnp3_header = { 05 64 }
    $warm_restart = { 0e }
  condition:
    $dnp3_header at 0 and $warm_restart at 12 and #dnp3_header < 2
}

rule broadcast_request : DNP3
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Client sending broadcast request"
    uuid = "0d7be1ab27244756ae5f11b00fd37ac1" 
  strings:
    $dnp3_header = { 05 64 }
    $broadcast = { FF FF }
  condition:
    $dnp3_header at 0 and $broadcast at 4 and #dnp3_header < 2
}


rule unauthorized_write_req_to_plc : DNP3
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description= "Client is sending unauthorized write request"
    uuid = "03e323f2ffc94d4593b5487f882b1b79"
  strings:
    $dnp3_header = { 05 64 }
    $payload = /(\x02|\x04|\x05|\x06|\x09|\x0A|\x0F|\x12)/
  condition:
    $dnp3_header at 0 and $payload at 12 and #dnp3_header < 2
}

rule unauthorized_miscellaneous_req_to_plc : DNP3
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description= "Client is sending unauthorized request"
    uuid = "275a728dcd0b419dbf480a618fc13853"
  strings:
    $dnp3_header = { 05 64 }
    $payload = /(\x03|\x07|\x08|\x0B|\x0C|\x10|\x11|\x13|\x14|\x15|\x16|\x17|\x18|\x19|\x1A|\x1B|\x1C|\x1D|\x1E)/
  condition:
    $dnp3_header at 0 and $payload at 20 and #dnp3_header < 2
}

rule points_list : DNP3
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description= "Points List"
    uuid = "275a728dcd0b419dbf480a618fc13853"
  strings:
    $dnp3_header = { 05 64 }
    $list = { 81 }
    $payload = /(\x02|\x04|\x06|\x0a|\x0c|\x0e)/
  condition:
    $dnp3_header at 0 and $list at 12 and $payload at 14 and #dnp3_header < 2
}

rule function_code_request : DNP3
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description= "Function Code Request"
    uuid = "0a49ad1330134004a09469fe9f6fc0ae"
  strings:
    $dnp3_header = { 05 64 }
    $code_req = { 81 ?? 01 }
  condition:
    $dnp3_header at 0 and $code_req at 12 and #dnp3_header < 2
}

rule stop_application : DNP3
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Client sending stop application command"
    uuid = "12010549da5148508a53294062755d5a" 
  strings:
    $dnp3_header = { 05 64 }
    $stop_app = { 12 }
  condition:
    $dnp3_header at 0 and $stop_app at 12 and #dnp3_header < 2
}


rule link_status_scan : DNP3
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Link status scan"
    uuid = "0ce7610402b84de29f5c1bbf8b47529b" 
  strings:
    $dnp3_header = { 05 64 }
    $link_layer_control = { 05 c9 ?? 00 }    
  condition:
    $dnp3_header at 0 and $link_layer_control at 2 and #dnp3_header < 2
}


