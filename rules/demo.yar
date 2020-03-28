rule ExampleRule
{
    strings:
        $my_text_string = "google.com"
        $my_hex_string = { 8d }
        $my_hex_string2 = { 00 }

    condition:
        $my_text_string or $my_hex_string or $my_hex_string2
}
