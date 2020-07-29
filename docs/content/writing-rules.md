# Writting rules

Mole IDS rule system is built on top of yara. You can find information about
[writting basic yara rules](https://yara.readthedocs.io/en/v3.11.0/writingrules.html)

## Syntax

With Mole IDS we will be able to match network packets payloads instead of file
payloads, that means we will need to use Yara in a different way.

When you use Yara to find patterns on files you mainly define the `strings`
section and the `condition` one. Well, in Mole IDS, you will need to use the
`meta` section as well.

The `meta` section will help Mole IDS to determine when the rule must be
executed and match the defined pattern.

Moreover, think for a moment that Mole IDS will execute Yara rules for a stream
of data, which means it has a variable length or the order is not always the
same. 

## Extra meta fields

As said before, there are some key entries in the `meta` section that defined
how the rule have to be executed based on the traffic.

### uuid

Mole IDS does not use it at the moment. It is there for future purposes.

### type

Type of event. Possible values:

* alert
* log
* block

!!! warning
    At the moment Mole IDS only manages **alerts** so the unique type that is
    recognized by Mole IDS right now is álert´.

### proto

`proto` stands for protocol and it defines either network or transport
protocols. The Yara rules associated to that protocol will be elected among
others to be executed when all conditions are met.

Possible values:

#### Network

* IP

#### Transport

* TCP
* UDP
* SCTP

`proto` accepts the negation operator (`!`). This operator can be used at the
begining of the sting and its function is to negate the value. For example a
rule defined like `proto = "!tcp"` will be executed on the following protocols
`IP, UDP, and SCTP`.

!!! warning
    Mole IDS only recognize the following protocols:

    * IP
    * TCP
    * UDP
    * SCTP

### src

Origin address of the packet. It must be an ip address, list of ip address or
range of ip addresses.

Example values:

* 192.168.0.1
* 192.168.0.1/32
* 192.168.0.0/24
* 192.168.0.1,192.168.0.2

`src` also accepts the negation operator (`!`). You can use it like this
`!192.168.0.1,192.168.0.2` and Mole IDS will match traffic comming from any
address but not from those two.

### sport

Origin port of the packet. It can be a port, a list of ports or a range of ports.

Example values:

* 1234
* 1-10
* 10:100
* 1,2,3

`sport` also supports the negation operator (`!`). An example of using the
negation operation `sport = "!80,443"`.

### dst

Destination address of the packet. It must be an ip address, list of ip address
or range of ip addresses.

### dport

Destination port of the packet. It can be a port, a list of ports or a range of ports.

## Variables

Variables are handy utility for writing more generic rules or rules that can be
addapted to other environmentes esaly.

Variables are defined in the configuration file under the
[rules section](/getting-started/configuration-overview/#rules). They are
basically a set of `key:value`.

This variables can be only used in the `meta` section and Mole IDS has some
variables already defined and they can not be overwrite, those are:

* $tcp = tcp
* $udp = udp
* $sctp = sctp

Finally, there is a variable called `any` that can be used to define any soruce
or destination address as wel as any source or destination port.

## Examples

Following several rule examples.

### Example 1

```yara
rule ExampleRule {
  meta:
    description = "Port range from 1 to 1024"
    type = "alert"
    proto = "tcp"
    src = "any"
    sport = "any"
    dst = "any"
    dport = "1:1024"
  strings:
    $dnp3_header = { 05 64 }
    $unsolicited_response = { 82 }
  condition:
    $dnp3_header at 0 and $unsolicited_response at 12 and #dnp3_header < 2
}
```
