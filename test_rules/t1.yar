rule Test1 : Foo Bar {
    meta:
        author = "Mole-IDS"
        type = "alert"
        uuid = "<not used>"
        proto = "tcp"
        src = "any"
        sport = "80"
        dst = "any"
        dport = "any"
    strings:
        $method = "GET"
    condition:
        $method at 0
}
