# Writting rules

Mole rule system is built on top of yara. You can find information about [writting basic yara rules](https://yara.readthedocs.io/en/v3.5.0/writingrules.html)

## Syntax

With Mole we will be able to match network packets payloads instead of file payloads, that means we will need to use Yara in a different way.


## Extra meta fields

### uuid

A universally unique identifier (UUID) is a 128-bit number used to identify rules.

In its canonical textual representation, the 16 octets of a UUID are represented as 32 hexadecimal (base-16) digits, displayed in five groups separated by hyphens, in the form 8-4-4-4-12 for a total of 36 characters (32 hexadecimal characters and 4 hyphens). For example:

1b453696-9e16-11ea-bb37-0242ac130002 

### type

Type of event. Possible values:

- alert
- log
- block

### proto

Protocol. Possible values:

- ip
- tcp

### src

Origin address of the packet. It must be an ip address, netmask, list of ip address or range of ip addresses. 

### sport

Origin port of the packet. It can be a port, a list of ports or a range of ports.

### dst

Destination address of the packet. It must be an ip address, netmask, list of ip address or range of ip addresses. 


### dport

Destination port of the packet. It can be a port, a list of ports or a range of ports.


## Variables

TBD

## Ranges


TBD

