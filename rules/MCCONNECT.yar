rule mcconnect_ascii_batch_write_in_bits : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "BATCH WRITE IN BITS (ASCII MESSAGE)"
    uuid = "d29ccbd54606453da742a7a45dafe926"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 31 30 30 ?? 31}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_batch_write_in_bits : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "BATCH WRITE IN BITS (BINARY MESSAGE)"
    uuid = "2d4dd0b945094ae1aae812f031fe03fc"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {01 14 ?1 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_batch_write_in_word : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "BATCH WRITE IN WORD (ASCII MESSAGE)"
    uuid = "2d4dd0b945094ae1aae812f031fe03fc"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 31 30 30 ?? 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_batch_write_in_word : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "BATCH WRITE IN WORD (BINARY MESSAGE)"
    uuid = "c895edc996264e4985fb6d7d8d26d18b"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {01 14 ?0 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_write_random_in_bits_test : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "DEVICE RANDOM WRITE IN BITS (ASCII MESSAGE)"
    uuid = "abb8992acb62432ca57867d595664c45"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 32 30 30 ?? 31}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_write_random_in_bits_test : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "DEVICE RANDOM WRITE IN BITS (BINARY MESSAGE)"
    uuid = "f041f868fdd8488ab49023dd1290ee79"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {02 14 ?1 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_write_random_in_word_test : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "DEVICE WRITE RANDOM IN WORD (ASCII MESSAGE)"
    uuid = "fac13362065d4b8bb62b01f0315eaeae"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 32 30 30 ?? 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_write_random_in_word_test : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "DEVICE WRITE RANDOM IN WORD (BINARY MESSAGE)"
    uuid = "66acb91f9bd64bc6ba8cf0432ae1aa0c"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {02 14 ?0 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_multiple_block_batch_write : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "MULTIPLE BLOCK BATCH WRITE (ASCII MESSAGE)"
    uuid = "b6a5561b0c894ca19f2d0845138beea9"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 36 30 30 ?? 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_multiple_block_batch_write : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "MULTIPLE BLOCK BATCH WRITE (BINARY MESSAGE)"
    uuid = "0bf495d38aff44c1972e2a80c56c572c"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {06 14 ?0 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_inteligent_function_buffer_memory_write : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "INTELIGENT FUNCTION BUFFER MEMORY WRITE (ASCII MESSAGE)"
    uuid = "cafb59470b19421d992df63d113f796a"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 36 30 31 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_inteligent_function_buffer_memory_write : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "INTELIGENT FUNCTION BUFFER MEMORY WRITE (BINARY MESSAGE)"
    uuid = "96797179a2a646d1a8ad41c682d07f87"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {01 16 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_buffer_memory_write : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "BUFFER MEMORY WRITE (ASCII MESSAGE)"
    uuid = "88574ecb5ccf4bcc92f55e58e6b57c47"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 36 31 33 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_buffer_memory_write : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "BUFFER MEMORY WRITE (BINARY MESSAGE)"
    uuid = "4cfd5f4319f2450ead1051ee7be96731"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {13 16 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_remote_run : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE RUN (ASCII MESSAGE)"
    uuid = "676538f35d6844cd8f595c4dc0161c2a"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 31 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_remote_run : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE RUN (BINARY MESSAGE)"
    uuid = "ef24d68289194afabcd1b8915fb40b37"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {01 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_remote_stop : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE STOP (ASCII MESSAGE)"
    uuid = "75ade8c997014006989a2178efd9249e"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 32 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_remote_stop : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE STOP (BINARY MESSAGE)"
    uuid = "2bf24b0fdef746e4ae7b724b981c8b9f"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {02 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_remote_pause : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE PAUSE (ASCII MESSAGE)"
    uuid = "e84dfe27773946778f3701a4a0825e56"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 33 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_remote_pause : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE PAUSE (BINARY MESSAGE)"
    uuid = "73bcaddd0b5b486caf46bc71c51d7f93"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {03 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_remote_latch_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE LATCH (ASCII MESSAGE)"
    uuid = "91b37121f2224206b3b8fb1a7b3cc9fa"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 35 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_remote_latch_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE LATCH (BINARY MESSAGE)"
    uuid = "0cd769b8c51d4c1da3ab4ff6b894a979"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {05 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_remote_reset_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE RESET (ASCII MESSAGE)"
    uuid = "f5e1ccdb62e04170aeda70f33fa1628c"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 36 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_remote_reset_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE RESET (BINARY MESSAGE)"
    uuid = "1989c4304d024be89990d8ba40b07280"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {06 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_information_modification_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE INFORMATION MODIFICATION (ASCII MESSAGE)"
    uuid = "4cec2e37bdef46d28671b57dbe702157"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 32 30 34 30 30 30 ??}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_information_modification_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE INFORMATION MODIFICATION (BINARY MESSAGE)"
    uuid = "db72a720507e47c5b5adc2332423a7bb"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {04 12 0? 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_write_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE WRITE (ASCII MESSAGE)"
    uuid = "af6747539a204d4caf6f11a34d2c31cd"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 32 30 33 30 30 30 ??}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_write_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE WRITE (BINARY MESSAGE)"
    uuid = "013e78a00d99472fbee4aef54bc717d6"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {03 12 0? 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_copy_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE COPY (ASCII MESSAGE)"
    uuid = "e4db333f8a024f3ca483d1727bf311b1"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 32 30 36 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_copy_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE COPY (BINARY MESSAGE)"
    uuid = "a7328e53828842a789930fa794dfa8f3"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {06 12 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_delete_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE DELETE (ASCII MESSAGE)"
    uuid = "35febdb6db9f4040ac2aab7c445f97d0"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 32 30 35 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_delete_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE DELETE (BINARY MESSAGE)"
    uuid = "c05a8cc8f067476d984087c42cdfba23"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {05 12 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_write_slmp_compatible_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE WRITE SLMP COMPATIBLE(ASCII MESSAGE)"
    uuid = "4981284793b2481f9dc13deeaecd8e66"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 39 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_write_slmp_compatible_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE WRITE SLMP COMPATIBLE(BINARY MESSAGE)"
    uuid = "2a28f6b270e245e998030ad95ccbe72b"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {29 18 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_copy_slmp_compatible_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE COPY SLMP COMPATIBLE(ASCII MESSAGE)"
    uuid = "6f971df0582c444185ade91a3829533c"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 34 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_copy_slmp_compatible_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE COPY SLMP COMPATIBLE(BINARY MESSAGE)"
    uuid = "e4c09ef43d55412bb9f01834067c530f"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {24 18 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_delete_slmp_compatible_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE DELETE SLMP COMPATIBLE(ASCII MESSAGE)"
    uuid = "8a1410d2eb4845da97ff0a44a1d48a28"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 32 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_delete_slmp_compatible_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE DELETE SLMP COMPATIBLE(BINARY MESSAGE)"
    uuid = "2079768275b54b849a41fc8cdac03fc6"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {22 18 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_creation_date_modification_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE CREATION DATE MODIFICATION(ASCII MESSAGE)"
    uuid = "e1cf97b09eea4e0fa4cf72f9de6943eb"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 36 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_creation_date_modification_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE CREATION DATE MODIFICATION(BINARY MESSAGE)"
    uuid = "67e159d1f3a14431b00f0e19e0c2957c"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {26 18 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_attribute_modification_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE ATTRIBUTE MODIFICATION(ASCII MESSAGE)"
    uuid = "d0bc33e27f3d426599bdcea4e93090c8"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 35 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_attribute_modification_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "FILE ATTRIBUTE MODIFICATION(BINARY MESSAGE)"
    uuid = "59a04c02753d40cbb872c5f3b2f3bd1c"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {25 18 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_remote_password_unlock_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE PASSWORD UNLOCK(ASCII MESSAGE)"
    uuid = "9d18094d14e74373b0bc7132289ef0a4"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 36 33 30 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_remote_password_unlock_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE PASSWORD UNLOCK(BINARY MESSAGE)"
    uuid = "7142905d32f446948f96045fd0cfdb7e"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {30 16 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_remote_password_lock_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE PASSWORD LOCK(ASCII MESSAGE)"
    uuid = "14ee839ca8b74534a3c3ba8fe35a54f6"
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 36 33 31 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_remote_password_lock_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Jose Fernando Gomez <jose.fernando.gomez@puffinsecurity.com>"
    description = "REMOTE PASSWORD LOCK(BINARY MESSAGE)"
    uuid = "536493a016f548f28585754979152281"
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {31 16 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

