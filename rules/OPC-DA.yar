rule OPCDA_IOPCBrowse_v180402 : OPC_DA
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "IOPCBrowse 39227004-a18f-4b57-8b0a-5235670f4468"
    uuid = "acf5480a10e54a1e91bf5232fc982e3b" 
  strings:
    $opc_da_header = { 05 00 ?? 03 10 00 00 00 }
    $IOPCBrowse = { 04 70 22 39 8f a1 57 4b 8b 0a 52 35 67 0f 44 68 }
  condition:
    $opc_da_header at 0 and $IOPCBrowse
}


rule OPCDA_IOPCEnumGUID_v180402 : OPC_DA
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "IOPCEnumGUID 55c382c8-21c7-4e88-96c1-becfb1e3f483"
    uuid = "ceaba4a1323f4736b41880b02ea9a723" 
  strings:
    $opc_da_header = { 05 00 ?? 03 10 00 00 00 }
    $IOPCEnumGUID = { c8 82 c3 55 21 c7 4e 88 96 c1 be cf b1 e3 f4 83 }
  condition:
    $opc_da_header at 0 and $IOPCEnumGUID
}

rule OPCDA_IOPCServerList2_v180402 : OPC_DA
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "IOPCServerList2 9dd0b56c-ad9e-43ee-8305-487f3188bf7a "
    uuid = "4913506dfb634e509955311052d1f5b9" 
  strings:
    $opc_da_header = { 05 00 ?? 03 10 00 00 00 }
    $IOPCServerList2 = { 6c b5 d0 9d ad 9e 43 ee 83 05 48 7f 31 88 bf 7a}
  condition:
    $opc_da_header at 0 and $IOPCServerList2
}

