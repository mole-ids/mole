rule yokogawa_CENTUM_CS_3000_exploit : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "SCADA Yokogawa CENTUM CS 3000 stack buffer overflow attempt"
    uuid = "eb67920d151f47d6bc93dbc35f0ab8e7"
    CVE = "CVE-2014-0783"
    dst_port = "20171"
  strings: 
    $payload = { 64 A1 18 00 00 00 83 C0 08 8B 20 81 C4 30 F8 FF FF }
  condition: 
    $payload
}

rule wonderware_InBatch_exploit : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Wonderware InBatch Buffer Overflow Attempt"
    uuid = "b9560c545fd34c19b8a5097d99a68682"
    CVE = "CVE-2010-4557"
    dst_port = "9001"
  strings: 
    $payload = { 00 00 4b 14 00 00 00 00 00 00 00 01 00 00 00 00 00 01 00 00 }
  condition: 
    $payload
}

rule realwin_HMI_exploit_1 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "RealWin HMI Service Buffer Overflow Attempt 1"
    CVE = "CVE-2010-4142"    
    uuid = "2172a9411229434c9c98ffb204c30cf8"
    dst_port = "912"
  strings: 
    $payload = { 64 12 54 6a 02 00 00 00 }
  condition: 
    $payload
}

rule realwin_HMI_exploit_2 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "RealWin HMI Service Buffer Overflow Attempt 2"
    CVE = "CVE-2010-4142"
    uuid = "90df1e95876b4d12b45f9884d0ae25ba"
    dst_port = "912"
  strings: 
    $payload = { 64 12 54 6a 20 00 00 00 }
  condition: 
    $payload
}

rule realwin_HMI_exploit_3 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "RealWin HMI Service Buffer Overflow Attempt 3"
    CVE = "CVE-2010-4142"    
    uuid = "6e2bf248e3074324ab3e434facc4f189"
    dst_port = "912"
  strings: 
    $payload = { 64 12 54 6a 10 00 00 00 }
  condition: 
    $payload
}


rule realwin_HMI_exploit_4 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "RealWin HMI Service Buffer Overflow Attempt 4"
    CVE = "CVE-2010-4142"    
    uuid = "5424275bcfae4af7a3c854089e76d537"
    dst_port = "912"
  strings: 
    $payload = { 64 12 54 6a 10 00 00 00 }
  condition: 
    $payload
}


rule Genesis_SCADA_free_unitialized_1 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Freeing of Unitialized Memory Trigger Option 1"
    uuid = "c519d883c2914b7cb03424e57fe192e1"
    dst_port = "38080"
  strings: 
    $payload = { b0 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff 0f 00 00 ff 0f 00 00 }
  condition: 
    $payload
}


rule Genesis_SCADA_free_unitialized_2 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Freeing of Unitialized Memory Trigger Option 2"
    uuid = "406183b8f61e46988c985d7742c17ab9"
    dst_port = "38080"
  strings: 
    $payload = { B2 04 00 00 FF 0F 00 00 }
  condition: 
    $payload
}


rule Genesis_SCADA_free_unitialized_3 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Freeing of Unitialized Memory Trigger Option 3"
    uuid = "dff27e5792774e27a4dcde72d4c5b95f"
    dst_port = "38080"
  strings: 
    $payload = { b5 04 00 00 00 00 00 00 00 00 00 00 00 00 ff 0f 00 00 }
  condition: 
    $payload
}

rule Genesis_SCADA_free_unitialized_4 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Freeing of Unitialized Memory Trigger Option 4"
    uuid = "c55b17fc7c9246d7a6a00ee06e859061"
    dst_port = "38080"
  strings: 
    $payload = { AE 0D 00 00 FF 0F 00 00 }
  condition: 
    $payload
}


rule Genesis_SCADA_free_unitialized_5 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Freeing of Unitialized Memory Trigger Option 5"
    uuid = "b7942bf043554023bfe90617aaa1e388"
    dst_port = "38080"
  strings: 
    $payload = { bc 1b 00 00 00 00 00 00 00 00 00 00 00 ff 0f 00 00}
  condition: 
    $payload
}


rule IGSS_Directory_Transversal_Download : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "IGSS SCADA System Directory Traversal and Download"
    uuid = "31d2da9ce9ba455b9b1571d9bab65bda"
    dst_port = "12401"
  strings: 
    $header = { 01 00 34 12 0D }
    $command = { 03 }
    $payload3 = { 2E 2E 5C 2E 2E 5C 2E 2E 5C 2E 2E 5C }
  condition: 
    $header at 2 and $command at 18 and $payload3 
}

rule IGSS_Directory_Transversal_Upload_Overwrite : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "IGSS SCADA system Directory Traversal Upload and Overwrite"
    uuid = "8fa2dc720e7046aa970fd2cdc6418608"
    dst_port = "12401"
  strings: 
    $header = { 01 00 34 12 0D }
    $command = { 02 }
    $payload3 = { 2E 2E 5C 2E 2E 5C 2E 2E 5C 2E 2E 5C }
  condition: 
    $header at 2 and $command at 18 and $payload3 
}


rule ROCKWELL_ControlLogix_Stop_CPU_DoS : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "ROCKWELL Automation ControlLogix Denial of Service (CPU Stop)"
    uuid = "e7001f647a804d5886cd9e8555d86c2a"
    osvdb = "78489"
    dst_port = "44818"
  strings: 
    $payload1 = { 6f 00 }
    $payload2 = { 00 00 00 00 }
    $payload3 = { b2 00 }
    $payload4 = { 52 }
    $payload5 = { 07 }
  condition: 
    $payload1 at 0 and $payload2 at 22 and $payload3 at 28 and $payload4 at 31 and $payload5 at 34
}

rule ROCKWELL_ControlLogix_Crash_CPU_DoS : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "ROCKWELL Automation ControlLogix Denial of Service (Crash CPU)"
    uuid = "be7c13b5d42244e3893efe0b32a9e0d7"
    osvdb = "78486"
    dst_port = "44818"
  strings: 
    $payload1 = { 6f 00 }
    $payload2 = { 00 00 00 00 }
    $payload3 = { b2 00 }
    $payload4 = { 52 }
    $payload5 = { 0a }
  condition: 
    $payload1 at 0 and $payload2 at 22 and $payload3 at 28 and $payload4 at 31 and $payload5 at 34
}


rule ROCKWELL_ControlLogix_EtherNET_Dump_Code : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "ROCKWELL Automation ControlLogix EtherNET/IP modules boot code dump (Dump)"
    uuid = "6bdb255475574fa9be2642a3054af699"
    osvdb = "osvdb"
    dst_port = "44818"
  strings: 
    $payload1 = { 6f 00 }
    $payload2 = { 00 00 00 00 }
    $payload3 = { b2 00 }
    $payload4 = { 97 02 20 c0 24 }
  condition: 
    $payload1 at 0 and $payload2 at 22 and $payload3 at 28 and $payload4 at 31 
}


rule ROCKWELL_ControlLogix_EtherNET_DoS : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "ROCKWELL Automation ControlLogix EtherNET/IP reset command Denial Of Service"
    uuid = "7de76e243a4e4704903a434f4da52a60"
    osvdb = "78491"
    dst_port = "44818"
  strings: 
    $payload1 = { 6f 00 }
    $payload2 = { 00 00 00 00 }
    $payload3 = { b2 00 }
    $payload4 = { 05 }
    $payload5 = { 20 01 }
  condition: 
    $payload1 at 0 and $payload2 at 22 and $payload3 at 28 and $payload4 at 31 and $payload5 at 32
}




rule ROCKWELL_ControlLogix_Crash : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "ROCKWELL Automation ControlLogix Crash 1756-ENBT module (CrashEth)"
    uuid = "6965f046a7044233ba397ca5e4ee7736"
    osvdb = "78487"
    dst_port = "44818"
  strings: 
    $payload1 = { 6f 00 }
    $payload2 = { 00 00 00 00 }
    $payload3 = { b2 00 }
    $payload4 = { 0e }
    $payload5 = { 20 f5 }
  condition: 
    $payload1 at 0 and $payload2 at 22 and $payload3 at 28 and $payload4 at 31 and $payload5 at 32
}

rule ROCKWELL_ControlLogix_Update_Firmware : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "ROCKWELL Automation ControlLogix EtherNET/IP Initialize the device to update the firmware (FlashUp)"
    uuid = "15c4f67ee92d4e3e8300f5188cd69b5f"
    osvdb = "78492"
    dst_port = "44818"
  strings: 
    $payload1 = { 6f 00 }
    $payload2 = { 00 00 00 00 }
    $payload3 = { b2 00 }
    $payload4 = { 4b }
    $payload5 = { 20 a1 }
  condition: 
    $payload1 at 0 and $payload2 at 22 and $payload3 at 28 and $payload4 at 31 and $payload5 at 32
}

rule schneider_quantumn_request_memory_card_id : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Schneider PLC(Quantumn) uses function code 90 for communications the Unity pro software Request Memory Card ID"
    uuid = "e47d9f6fd75b481fa0ed7bb7aade4662"
    dst_port = "502"
  strings: 
    $modbus = { 00 00 }
    $req = { 5a }
    $payload = { 00 06 06 }
  condition: 
    $modbus at 2 and $req at 7 and $payload at 8

}



rule schneider_quantumn_request_cpu_module_info : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Schneider PLC(Quantumn) uses function code 90 for communications the Unity pro software Request CPU Module info"
    uuid = "369fd020ec474ce9a265a6f4cbea1606"
    dst_port = "502"
  strings: 
    $modbus = { 00 00 }
    $req = { 5a }
    $payload = { 00 02 }
  condition: 
    $modbus at 2 and $req at 7 and $payload at 8

}

rule schneider_quantumn_request_project_filename : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Schneider PLC(Quantumn) uses function code 90 for communications the Unity pro software Request Project file name"
    uuid = "744ae9d142954c919fd0661ce8a22643"
    dst_port = "502"
  strings: 
    $modbus = { 00 00 }
    $req = { 5a }
    $payload = { f6 00 }
  condition: 
    $modbus at 2 and $req at 7 and $payload at 8

}

rule schneider_quantumn_request_project_info : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Schneider PLC(Quantumn) uses function code 90 for communications the Unity pro software Request Project Information(Revision and Last Modified)"
    uuid = "317eb8cb3d92403bb5a75291c4fbe033"
    dst_port = "502"
  strings: 
    $modbus = { 00 00 }
    $req = { 5a }
    $payload = { 03 00 }
  condition: 
    $modbus at 2 and $req at 7 and $payload at 17

}

rule schneider_quantumn_set_plc_cpu_stop : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Schneider PLC(Quantumn) uses function code 90 for communications the Unity pro software Set PLC CPU STOP"
    uuid = "3863d163716341f581029ecf308a137b"
    dst_port = "502"
  strings: 
    $modbus = { 00 00 }
    $req = { 5a }
    $payload = { 40 }
  condition: 
    $modbus at 2 and $req at 7 and $payload at 9

}

rule schneider_quantumn_set_plc_cpu_restart : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Schneider PLC(Quantumn) uses function code 90 for communications the Unity pro software Set PLC CPU Restart"
    uuid = "3d97e18e4faf4d668da86e6a76857b56"
    dst_port = "502"
  strings: 
    $modbus = { 00 00 }
    $req = { 5a }
    $payload = { 41 }
  condition: 
    $modbus at 2 and $req at 7 and $payload at 9

}

rule HatMan_inject_payload : ICS_ATTACK
{
  meta:
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    description = "HatMan inject payload"
    uid = "8b6b5ba8d10e4c379a89303345d893c8"
    dst_port = "1502"
 strings:
    $payload_inject = { 05 00 0A 00 00 00 13 02 00 00 29 00 0A 00 71 38 }
  condition:
    $payload_inject at 0
}



rule IGSS_Directory_Transversal_Arbitrary_File_Execution_0x0A : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "IGSS SCADA dc.exe Server Directory Traversal Arbitrary File Execution - 0xa"
    uuid = "148d3fb579e04140972ffa79f86e20c2"
    dst_port = "12397"
  strings: 
    $header = { 0A }
    $payload = { 2E 2E 5C 2E 2E 5C 2E 2E 5C 2E 2E 5C 2E 2E 5C }
  condition: 
    $header at 12 and $payload at 13
}




rule IGSS_Directory_Transversal_Arbitrary_File_Execution_0x17 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "IGSS SCADA dc.exe Server Directory Traversal Arbitrary File Execution - 0x17"
    uuid = "8ef206bdf8404dbeb19b95572b54aadc"
    dst_port = "12397"
  strings: 
    $header = { 17 }
    $payload = { 2E 2E 5C 2E 2E 5C 2E 2E 5C 2E 2E 5C 2E 2E 5C }
  condition: 
    $header at 12 and $payload at 13
}



rule Iconics_Genesis_SCADA_Integer_Overflow_0x9a08 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Integer Overflow 0x9a08"
    uuid = "4f276cb9fe044b91bb8699acf98fdf2f"
    dst_port = "38080"
  strings: 
    $payload = { 01 00 00 15 00 00 00 01 00 00 1F F4 01 00 00 00 }
    $payload2 = { 9A 08 }
  condition: 
    $payload and $payload2
}


rule Iconics_Genesis_SCADA_Integer_Overflow_0x5304 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Integer Overflow 0x5304"
    uuid = "1fff033672444c61b16c0521659989a4"
    dst_port = "38080"
  strings: 
    $payload = { 01 00 00 15 00 00 00 01 00 00 1F F4 01 00 00 00 }
    $payload2 = { 53 04 }
  condition: 
    $payload and $payload2
}

rule Iconics_Genesis_SCADA_Integer_Overflow_0x04b0 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Integer Overflow 0x04b0"
    uuid = "df59676424da4bc1a34a03ba6f30b44c"
    dst_port = "38080"
  strings: 
    $payload = { 01 00 00 15 00 00 00 01 00 00 1F F4 01 00 00 00 }
    $payload2 = { B0 04 }
  condition: 
    $payload and $payload2
}

rule Iconics_Genesis_SCADA_Integer_Overflow_0x04b2 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Integer Overflow 0x04b2"
    uuid = "c3fd9246fdc14405acd843d8991e75be"
    dst_port = "38080"
  strings: 
    $payload = { 01 00 00 15 00 00 00 01 00 00 1F F4 01 00 00 00 }
    $payload2 = { B2 04 }
  condition: 
    $payload and $payload2
}

rule Iconics_Genesis_SCADA_Integer_Overflow_0x04b5 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Integer Overflow 0x04b5"
    uuid = "5549e00858ad4c2c978a973e58efb427"
    dst_port = "38080"
  strings: 
    $payload = { 01 00 00 15 00 00 00 01 00 00 1F F4 01 00 00 00 }
    $payload2 = { B5 04 }
  condition: 
    $payload and $payload2
}

rule Iconics_Genesis_SCADA_Integer_Overflow_0x7d0 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Integer Overflow 0x7d0"
    uuid = "fa0d62dcd88e47e1b1a1d0c353f69754"
    dst_port = "38080"
  strings: 
    $payload = { 01 00 00 15 00 00 00 01 00 00 1F F4 01 00 00 00 }
    $payload2 = { D0 07 }
  condition: 
    $payload and $payload2
}

rule Iconics_Genesis_SCADA_Integer_Overflow_0xdae : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Integer Overflow 0xdae"
    uuid = "26c6db9e26b7411a88dab98ecb9feb9c"
    dst_port = "38080"
  strings: 
    $payload = { 01 00 00 15 00 00 00 01 00 00 1F F4 01 00 00 00 }
    $payload2 = { AE 0D }
  condition: 
    $payload and $payload2
}

rule Iconics_Genesis_SCADA_Integer_Overflow_0xfa4 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Integer Overflow 0xfa4"
    uuid = "162ba64ee4ca46e2b4cc9fde1ab208d8"
    dst_port = "38080"
  strings: 
    $payload = { 01 00 00 15 00 00 00 01 00 00 1F F4 01 00 00 00 }
    $payload2 = { A4 0F }
  condition: 
    $payload and $payload2
}

rule Iconics_Genesis_SCADA_Integer_Overflow_0xfa7 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Integer Overflow 0xfa7"
    uuid = "aadefb6a39484fc6bac0c6a05ad9d219"
    dst_port = "38080"
  strings: 
    $payload = { 01 00 00 15 00 00 00 01 00 00 1F F4 01 00 00 00 }
    $payload2 = { A7 0F }
  condition: 
    $payload and $payload2
}

rule Iconics_Genesis_SCADA_Integer_Overflow_0x1bbc : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Integer Overflow 0x1bbc"
    uuid = "25f59cf876984c98abeaa8278645ae14"
    dst_port = "38080"
  strings: 
    $payload = { 01 00 00 15 00 00 00 01 00 00 1F F4 01 00 00 00 }
    $payload2 = { BC 1B }
  condition: 
    $payload and $payload2
}

rule Iconics_Genesis_SCADA_Integer_Overflow_0x1c84 : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Integer Overflow 0x1c84"
    uuid = "a9905b93970a4e75a4cc99536305a579"
    dst_port = "38080"
  strings: 
    $payload = { 01 00 00 15 00 00 00 01 00 00 1F F4 01 00 00 00 }
    $payload2 = { 84 1C }
  condition: 
    $payload and $payload2
}

rule Iconics_Genesis_SCADA_Integer_Overflow_0x26ac : ICS_ATTACK 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Iconics Genesis SCADA Integer Overflow 0x26ac"
    uuid = "f3d3747de15749b9b78df14e748d6bc6"
    dst_port = "38080"
  strings: 
    $payload = { 01 00 00 15 00 00 00 01 00 00 1F F4 01 00 00 00 }
    $payload2 = { AC 26 }
  condition: 
    $payload and $payload2
}




