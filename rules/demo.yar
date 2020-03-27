rule ExampleRule
{
    strings:
        $my_text_string = "text here"
        $my_hex_string = { 41 }

    condition:
        $my_text_string or $my_hex_string
}