rule force_listen_only_mode : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Force Listen Only Mode"
    uuid = "1e0af54bf2fd4e75aa985608f3a0c361"
  strings: 
    $modbus_header = { 00 00 }
    $force_listen = { 08 00 04 }
  condition: 
    $modbus_header at 2 and $force_listen at 7
}

rule restart_communications_option : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Restart Communications Option"
    uuid = "dadb0f5fb6144db981a06bd706646c80"
  strings: 
    $modbus_header = { 00 00 }
    $restart = { 08 00 01 }
  condition: 
    $modbus_header at 2 and $restart at 7
}

rule clear_counters_and_diagnostic_registers : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Clear Counters and Diagnostic Registers"
    uuid = "5bc4878a009942dd8fdefe9e91e24a70"
  strings: 
    $modbus_header = { 00 00 }
    $clear_diag = { 08 00 0a }
  condition: 
    $modbus_header at 2 and $clear_diag at 7
}


rule report_server_information : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Report Server Information"
    uuid = "12f58835ee0341b5b563577700ab479c"
  strings: 
    $modbus_header = { 00 00 }
    $report_server_info = { 11 }
  condition: 
    $modbus_header at 2 and $report_server_info at 7
}



rule slave_device_busy_exception_code_delay : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Slave Device Busy Exception Code Delay"
    uuid = "9adde64659e24456badb74be64d315ce"
  strings: 
    $modbus_header = { 00 00 }
    $busy = { 06 }
    $payload = { 80 }
  condition: 
    $modbus_header at 2 and $busy at 8 and $payload at 7
}

rule ack_exception_code_delay : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Acknowledge Exception Code Delay"
    uuid = "52cf133f7ec543388d6a90bdc2a219fe"
  strings: 
    $modbus_header = { 00 00 }
    $ack = { 05 }
    $payload = { 80 }
  condition: 
    $modbus_header at 2 and $ack at 8 and $payload at 7
}

rule points_list_scan : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Points List"
    uuid = "51325c4b7a35415dbfa77360b031a451"
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 80 }
    $points_list = { 02 }
  condition: 
    $modbus_header at 2 and $payload at 7 and $points_list at 8
}

rule function_code : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Function code"
    uuid = "1a09d6f501004b168e3b85ff46fac53b"
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 80 }
    $points_list = { 01 }
  condition: 
    $modbus_header at 2 and $payload at 7 and $points_list at 8
}



rule Modbus_TCP_Write_single_coil : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Modbus TCP/Write Single Coil"
    uuid = "a6be02ca588341fa9318ca8330c0f9f8"
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 05 }
  condition: 
    $modbus_header at 2 and $payload at 7 
}



rule Modbus_TCP_Write_single_register : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Modbus TCP/Write Single Register"
    uuid = "04904d0e255e436d8519fa2b1dcbf7bb"
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 06 }
  condition: 
    $modbus_header at 2 and $payload at 7 
}



rule Modbus_TCP_Read_Exception_Status : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Modbus TCP/Read Exception Status"
    uuid = "4a81b3de62d74600b557cf17e28345d5"
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 07 }
  condition: 
    $modbus_header at 2 and $payload at 7 
}




rule Modbus_TCP_Diagnostics_Device : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Modbus TCP/Diagnostics Device"
    uuid = "cdba7682c5404eb7b4f2077252752ab9"
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 08 }
  condition: 
    $modbus_header at 2 and $payload at 7 
}




rule Modbus_TCP_Write_Multiple_Coils : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Modbus TCP/Write Multiple Coils"
    uuid = "be6d7d1694e44deeae195bee99011ce5"
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 0f }
  condition: 
    $modbus_header at 2 and $payload at 7 
}



rule Modbus_TCP_Write_Multiple_registers : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Modbus TCP/Write Multiple registers"
    uuid = "7ffea98b5f0e45448c4e8e3f5e7d371d"
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 10 }
  condition: 
    $modbus_header at 2 and $payload at 7 
}




rule Modbus_TCP_Write_File_Record : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Modbus TCP/Write File Record"
    uuid = "3a32a1948c8b49398b36f4b0b549ec3b"
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 15 }
  condition: 
    $modbus_header at 2 and $payload at 7 
}



rule Modbus_TCP_Write_Register : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Modbus TCP/Mask Write Register"
    uuid = "0e87e4a32de44013ba73df5f8ed268fa"
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 16 }
  condition: 
    $modbus_header at 2 and $payload at 7 
}


rule Modbus_TCP_Read_Write_Multiple_Registers : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Modbus TCP/Read/Write Multiple registers"
    uuid = "129082bb1a3f48fab882df6e30cd519f"
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 17 }
  condition: 
    $modbus_header at 2 and $payload at 7 
}


rule Modbus_TCP_Read_Device_Identification : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Modbus TCP/Read Device Identification"
    uuid = "e68410aee14244a985f372b88769bd2e"
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 2B }
  condition: 
    $modbus_header at 2 and $payload at 7 
}




rule unauthorized_read_request_plc : modbus 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Unauthorized Read Request to a PLC"
    uuid = "032d4d272ced432b804beb6dfeca98d1"
  strings: 
    $modbus_header = { 00 00 }
    $unauth_read_plc = /[\S\s]{3}(\x01|\x02|\x03|\x04|\x07|\x0B|\x0C|\x11|\x14|\x17|\x18|\x2B)/
  condition: 
    $modbus_header at 2 and $unauth_read_plc at 3
}







