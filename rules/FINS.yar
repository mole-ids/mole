rule memory_area_write : FINS 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "FINS memory area write"
    uuid = "8c059aa02b3c4941a06e8b620609cd99"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 01 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule stop_command : FINS 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "FINS Stop Command"
    uuid = "a3ed5327ecfe43d780637caaa9ac1415"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 04 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule invalid_command_area_clear : FINS 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "FINS invalid command: PROGRAM AREA CLEAR"
    uuid = "da35140cc2534fe38106dd7549715548"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 03 08 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule force_right_acquire : FINS 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "FINS Stop Command: ACCESS RIGHT FORCED ACQUIRE"
    uuid = "08131f969740423fb12906ddd6a0cb22"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 0C 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule error_clear : FINS 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "FINS ERROR CLEAR"
    uuid = "779adefb398245588973dc2afc04f36a"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 21 01 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule force_reset : FINS 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "FINS FORCED SET/RESET"
    uuid = "66c35fc338bf4ab3a73aebe5b0bd705a"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 23 01 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule memory_area_fill : FINS 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS MEMORY AREA FILL"
    uuid = "9a968a6364ee439ab535b3cd84f87ad4"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 01 03 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule memory_area_transfer : FINS 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS MEMORY AREA TRANSFER"
    uuid = "a4ed2d6ed7d947579bf63acc4c493583"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 01 05 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule parameter_area_write : FINS 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS PARAMETER AREA WRITE"
    uuid = "0b99c903454e43308d10a6036766a82c"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 02 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule parameter_area_clear : FINS 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS PARAMETER AREA CLEAR"
    uuid = "fd23dc96678847a1ae4beb82460cf06d"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 02 03 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule program_area_protect : FINS 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS PROGRAM AREA PROTECT"
    uuid = "98ed78a06c1d4420a471acd90b58c421"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 03 04 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule program_area_protect_clear : FINS 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS PROGRAM AREA PROTECT CLEAR"
    uuid = "5badd0c4b89e4c0492dd04cc5a6adf36"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 03 05 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule program_area_write : FINS 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS PROGRAM AREA WRITE"
    uuid = "4c70bfcdb3ce4669bbf90a771c97d140"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 03 07 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule program_area_clear : FINS 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS PROGRAM AREA CLEAR"
    uuid = "b782253da1ef4239b7cf62a45c2a81dc"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 03 08 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule error_log_clear : FINS 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS ERROR LOG CLEAR"
    uuid = "62bacca4ad8548d8bc89259f95e2b13d"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 21 03 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule clock_write : FINS 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS CLOCK WRITE"
    uuid = "9cdd7b10989645479170fcdab35bc21c"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 07 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule run : FINS 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS RUN"
    uuid = "35b53b3722784b7288e38156f11094ce"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 04 01 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule forced_set_reset_cancel : FINS 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS SET RESET CANCEL"
    uuid = "ab8ed6c3926048d6901127cc71af12ed"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 23 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule data_link_table_write : FINS 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS DATA LINK TABLE WRITE"
    uuid = "10725d7ff6a646aab9be933a0ca6e641"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 02 21 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule name_delete : FINS 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS NAME DELETE"
    uuid = "f2d69d2b455f4870b7284352a6ad610b"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 26 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_single_file_write_binary_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS FILE WRITE"
    uuid = "6950d45a9f8548e1852e8aac5e929b27"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 03 ?? ?? 00 00 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_single_file_write_with_overwrite_binary_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS FILE WRITE WITH OVERWRITE"
    uuid = "70959b1b15c74b87bd3ef2f9256b40c7"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 03 ?? ?? 00 01 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_single_file_append_data_binary_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS FILE APPEND DATA"
    uuid = "50c51b97bf6a49a18ed385091a5b2bf7"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 03 ?? ?? 00 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_single_file_overwrite_binary_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS FILE OVERWRITE"
    uuid = "d62a8075ed73465aa2459f726dac7642"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 03 ?? ?? 00 03 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_memory_card_format_binary_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS MEMORY CARD FORMAT"
    uuid = "e801f112f1324772a299fe56ff10ebdf"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 04 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_file_delete_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS FILE DELETE"
    uuid = "7135c39bf7b64180ab187afc231d37cc"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 05 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_volume_label_create_binary_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS VOLUME LABEL CREATE"
    uuid = "c2e491386ccc42af97d1e801413c7a85"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 06 ?? ?? 00 00 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_volume_label_create_or_overwrite_binary_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS VOLUME LABEL CREATE OR OVERWRITE"
    uuid = "87ce011245444c5bb41fdf1084ad19fa"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 06 ?? ?? 00 01 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_volume_label_delete_binary_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS VOLUME LABEL DELETE"
    uuid = "0d2340a62d33417193ccb6a35a7c5349"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 06 ?? ?? 00 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_file_copy_binary_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS VOLUME LABEL DELETE"
    uuid = "ce73a402ac224f1b8979a71804ba387a"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 07 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_file_name_change_binary_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FINS VOLUME LABEL DELETE"
    uuid = "e2ee250284a844ab85b269f9e17daa2e"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 08 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_memory_area_file_transfer_pc_to_device_binary_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "MEMORY AREA FILE TRANSFER PC TO DEVICE"
    uuid = "ba35eaab08bf435ba9595afe9a2dc7f5"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 0A 00 00 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_memory_area_file_transfer_device_to_pc_binary_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "MEMORY AREA FILE TRANSFER DEVICE TO PC"
    uuid = "844de1d3359940f595daf59d9e56ec13"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 0A 00 01 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_parameter_area_file_transfer_pc_to_device_binary_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "PARAMETER AREA FILE TRANSFER PC TO DEVICE"
    uuid = "041badf6b7604e7689255d8e065a8222"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 0B 00 00 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_parameter_area_file_transfer_device_to_pc_binary_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "PARAMETER AREA FILE TRANSFER DEVICE TO PC"
    uuid = "85dcd601dc654068852630d0805d5dc0"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 0B 00 01 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_program_area_file_transfer_pc_to_device_binary_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "PROGRAM AREA FILE TRANSFER PC TO DEVICE"
    uuid = "7bf594c5147b4aa7890696139775751d"
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 0C 00 00 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_program_area_file_transfer_device_to_pc_binary_v180316 : FINS
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "PROGRAM AREA FILE TRANSFER DEVICE TO PC"
    uuid = "674e355f549d44de94779a6e11521b7b"
  strings:
    $fins_header = { 00 02 }
    $fins_command = { 22 0C 00 01 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}
