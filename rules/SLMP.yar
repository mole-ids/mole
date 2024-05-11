rule ascii_device_write_in_bits : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "DEVICE WRITE IN BITS (ASCII MESSAGE)"
    uuid = "cd9da45486274f7980fe63ad6213e3a2"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 31 30 30 ?? 31}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_device_write_in_bits : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "DEVICE WRITE IN BITS (BINARY MESSAGE)"
    uuid = "fcee1e46161e4730b69ab24599cb0dd7"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {01 14 ?1 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_device_write_in_word : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "DEVICE WRITE IN WORD (ASCII MESSAGE)"
    uuid = "38bd9a1d253647dc94b8ca7d768ed07b"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 31 30 30 ?? 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_device_write_in_word : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "DEVICE WRITE IN WORD (BINARY MESSAGE)"
    uuid = "224acbcdd76d43c796cb0371979edfd6"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {01 14 ?0 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_device_write_random_in_bits : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "DEVICE RANDOM WRITE IN BITS (ASCII MESSAGE)"
    uuid = "afc345357ce145c3974f32b12d99d2e1"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 32 30 30 ?? 31}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_device_write_random_in_bits : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "DEVICE RANDOM WRITE IN BITS (BINARY MESSAGE)"
    uuid = "984a0abfdc334ac9a01acb0cdc440fc7"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {02 14 ?1 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_device_write_random_in_word : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "DEVICE RANDOM WRITE IN WORD (ASCII MESSAGE)"
    uuid = "331c1bb9857446f1bc17aa697cd3f73a"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 32 30 30 ?? 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_device_write_random_in_word : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "DEVICE RANDOM WRITE IN WORD (BINARY MESSAGE)"
    uuid = "99c055c3b3074614ba9379c8dca0448e"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {02 14 ?0 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_device_write_block : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "DEVICE WRITE BLOCK (ASCII MESSAGE)"
    uuid = "9c1b08d80d4b4253a656920afb575603"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 36 30 30 ?? 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_device_write_block : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "DEVICE WRITE BLOCK (BINARY MESSAGE)"
    uuid = "bcf0f846f690461483c89a92ab533f3d"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {06 14 ?0 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_extend_unit_write : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "EXTEND UNIT WRITE (ASCII MESSAGE)"
    uuid = "d186845e7bcf455ca818fc736d122e90"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 36 30 31 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_extend_unit_write : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "EXTEND UNIT WRITE (BINARY MESSAGE)"
    uuid = "f018e893d65b4544b65b59bf106ad8f4"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {01 16 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_memory_write : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "MEMORY WRITE (ASCII MESSAGE)"
    uuid = "a0c5e30fbd7d4fcda42f35b60b7fc353"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 36 31 33 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_memory_write : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "MEMORY WRITE (BINARY MESSAGE)"
    uuid = "9049bbaa447643e88ebb9207599ec85e"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {13 16 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_remote_run : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE RUN (ASCII MESSAGE)"
    uuid = "0d0ee30b6b1f444f80d7d4012e418c24"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 31 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_remote_run : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE RUN (BINARY MESSAGE)"
    uuid = "afe7e83e5619465b9b713106979e6682"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {01 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_remote_stop : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE STOP (ASCII MESSAGE)"
    uuid = "905fb096a8ef40788c03d7bf86561fde"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 32 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_remote_stop : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE STOP (BINARY MESSAGE)"
    uuid = "b0cec95dd2ff4cb98daf7bc5082dd85d"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {02 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_remote_pause : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE PAUSE (ASCII MESSAGE)"
    uuid = "50c656b4d4c74978b4da0663c147a7e8"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 33 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_remote_pause : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE PAUSE (BINARY MESSAGE)"
    uuid = "02910ee7c6af43758cd5187c0f8ee826"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {03 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_remote_latch : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE LATCH (ASCII MESSAGE)"
    uuid = "191aa7393e29480fbc746b7b45892d48"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 35 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_remote_latch : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE LATCH (BINARY MESSAGE)"
    uuid = "8ed3c75f75164094b3085462fb96b645"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {05 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_remote_reset : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE RESET (ASCII MESSAGE)"
    uuid = "574136bc4117411d9e700b03e3f8ae08"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 36 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_remote_reset : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE RESET (BINARY MESSAGE)"
    uuid = "c3563353fe5646da9e4e7330634e3ff8"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {06 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_change_file_date : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "CHANGE FILE DATE (ASCII MESSAGE)"
    uuid = "fcb0b9dd25044e0ebb5adf26f471dd46"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 36 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_change_file_date : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "CHANGE FILE DATE (BINARY MESSAGE)"
    uuid = "0a179d6b85344cd5b96825c8dd8d12f9"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {26 18 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_write_file : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "WRITE FILE (ASCII MESSAGE)"
    uuid = "0671fd1e64614043b74575c548cfd753"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 39 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_write_file : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "WRITE FILE (BINARY MESSAGE)"
    uuid = "59db5373411c4d5d99f7a4cadcfaa252"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {29 18 00 00}
  condition:
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_copy_file : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "COPY FILE (ASCII MESSAGE)"
    uuid = "f502029b7706466c84c52649d59b19b4"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 34 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_copy_file : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "COPY FILE (BINARY MESSAGE)"
    uuid = "c683adab1cf84f209c778a147cdc5b25"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {24 18 00 00}
  condition:
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_delete_file : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "DELETE FILE (ASCII MESSAGE)"
    uuid = "f5980e41e9d349c3a1640e9a7f685646"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 32 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_delete_file : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "DELETE FILE (BINARY MESSAGE)"
    uuid = "fa70af0ce26543318481a51b3697326c"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {22 18 00 00}
  condition:
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_change_file_state : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "CHANGE FILE STATE (ASCII MESSAGE)"
    uuid = "4fae6b15fb5648df9ec9ad427f91572f"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 35 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_change_file_state : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "CHANGE FILE STATE (BINARY MESSAGE)"
    uuid = "05ebe1d21b5a4551aea3cce060f38917"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {25 18 00 00}
  condition:
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_remote_password_unlock : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "PASSWORD UNLOCK (ASCII MESSAGE)"
    uuid = "af0a7be363a1416b830cfa1d91c5a865"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 36 33 30 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_remote_password_unlock : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "PASSWORD UNLOCK (BINARY MESSAGE)"
    uuid = "d442a4433c7543fe88d9127c1cd4c229"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {30 16 00 00}
  condition:
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}


rule ascii_remote_password_lock : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "PASSWORD LOCK (ASCII MESSAGE)"
    uuid = "36be35b2630147e890a5e234c3e90527"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 36 33 31 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_remote_password_lock : SLMP 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "PASSWORD LOCK (BINARY MESSAGE)"
    uuid = "ba91f4030e904001bb179c9a6eb717ba"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {31 16 00 00}
  condition:
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}
