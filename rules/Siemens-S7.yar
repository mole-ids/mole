
rule Siemens_S7_Set_Clock : Siemens_S7
{
  meta:
    description = "Request Time functions/Set clock"
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "0d35a1d41247421aae837dfa57cd0638"
    dst_port = "102"
 strings:
    $header = { 03 00 }
    $payload1 = { 32 07 00 }
    $payload2 = { 00 01 12 04 11 47 02 00 }
  condition:
    $header at 0 and $payload1 at 7 and $payload2 at 17

}

rule Siemens_S7_Set_Password : Siemens_S7
{
  meta:
    description = "Request Security functions/Set PLC session password"
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "3350a6d871c74db39fc7cb765db9324e"
    dst_port = "102"
 strings:
    $header = { 03 00 }
    $payload = { 00 01 12 04 11 45 01 00 }
  condition:
    $header at 0 and $payload at 17

}

rule Siemens_S7_Set_CPU_Stop : Siemens_S7
{
  meta:
    description = "Request CPU functions/Set PLC CPU STOP"
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "c2a7529d561e463383f4ee579aafd913"
    dst_port = "102"
 strings:
    $payload = { 29 00 00 00 00 00 09 50 5f 50 52 4f 47 52 41 4d }
  condition:
    $payload 

}

rule Siemens_S7_Set_CPU_Hot_Restart : Siemens_S7
{
  meta:
    description = "Request CPU functions/Set PLC CPU Hot Restart"
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "98fcadd492454e008f36e2b72cf24b9a"
    dst_port = "102"
 strings:
    $payload = { 28 00 00 00 00 00 00 fd 00 00 09 50 5f 50 52 4f }
  condition:
    $payload 

}

rule Siemens_S7_Set_CPU_Cold_Restart : Siemens_S7
{
  meta:
    description = "Request CPU functions/Set PLC CPU Cold Restart"
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "708fe78b4c1646569024c422336673ac"
    dst_port = "102"
 strings:
    $payload = { 28 00 00 00 00 00 00 fd 00 02 43 20 09 50 5f 50 52 4f 47 52 41 4d }
  condition:
    $payload 

}

rule Siemens_S7_Write_Var : Siemens_S7
{
  meta:
    description = "Write Var"
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "893dfef82ca14a34a2bfffdcf7e5a425"
    dst_port = "102"
 strings:
    $header = { 03 00 }
    $payload = { 05 }
  condition:
    $header at 0 and $payload at 17

}

rule Siemens_S7_Request_Download : Siemens_S7
{
  meta:
    description = "Request download"
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "fde3a73ca62e42bfaa69bf4b3614f5da"
    dst_port = "102"
 strings:
    $header = { 03 00 }
    $payload = { 1a }
  condition:
    $header at 0 and $payload at 17

}

rule Siemens_S7_Download_Block : Siemens_S7
{
  meta:
    description = "Download block"
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "139a29d3f3ce48289bdc29a0178d6db5"
    dst_port = "102"
 strings:
    $header = { 03 00 }
    $payload1 = { 32 01 }
    $payload2 = { 1b }    
  condition:
    $header at 0 and $payload1 at 7 and $payload2 at 17

}

rule Siemens_S7_Download_Ended : Siemens_S7
{
  meta:
    description = "Download ended"
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "69902ca843d842fe9492105fefe0e4ad"
    dst_port = "102"
 strings:
    $header = { 03 00 }
    $payload1 = { 32 01 }
    $payload2 = { 1c }    
  condition:
    $header at 0 and $payload1 at 7 and $payload2 at 17

}

rule Siemens_S7_Start_Upload : Siemens_S7
{
  meta:
    description = "Start upload"
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "b8c3da7545394af4a22d41c792444a80"
    dst_port = "102"
 strings:
    $header = { 03 00 }
    $payload1 = { 32 01 }
    $payload2 = { 1d }    
  condition:
    $header at 0 and $payload1 at 7 and $payload2 at 17

}

rule Siemens_S7_Upload : Siemens_S7
{
  meta:
    description = "Upload"
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "26aa3e919bb24d3eb8c71d9964acb897"
    dst_port = "102"
 strings:
    $header = { 03 00 }
    $payload1 = { 32 01 }
    $payload2 = { 1e }    
  condition:
    $header at 0 and $payload1 at 7 and $payload2 at 17

}

rule Siemens_S7_End_Upload : Siemens_S7
{
  meta:
    description = "End upload"
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "4bb4a2c740ed4cefa871bf64a89c31eb"
    dst_port = "102"
 strings:
    $header = { 03 00 }
    $payload1 = { 32 01 }
    $payload2 = { 1f }    
  condition:
    $header at 0 and $payload1 at 7 and $payload2 at 17

}

rule Siemens_S7_Delete_Block : Siemens_S7
{
  meta:
    description = "Delete block"
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "2dcef8a3655a44eb97424a41ece101c1"
    dst_port = "102"
 strings:
    $header = { 03 00 }
    $payload = { 05 5f  }
 condition:
    $header at 0 and $payload

}





