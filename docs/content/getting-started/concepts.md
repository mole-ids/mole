# Concepts

Everything You Need to Know
{: .subtitle }

We are sure most of the Mole users already know mostly everything regarding
Network Intrusion Detection Systems, as well as the network patterns to capture
network traffic. However, people camming in to cybersecurity may need some initial
guiadence to start capturing traffic.

Mode IDS is an application that reads network traffic in a promiscuous way, that
means Mole IDS can read network traffic even when that traffic is not addressed
to be read by Mole IDS. That can be achieved first by configuring the netwotk
addapter in monitor mode (a.k.a promisc mode), second, other network adapters or
devices have to send traffic to Mole IDS, normally that can be done by using a
port mirror or a span port.

{{ image }}

Once the traffic is read Mole IDS analyze it based on rules so if there is a match
Mole IDS will fire an alert. Imagine you want to be alerted when some packet uses
a source port 31337 so you will need to write a rule that indicates to Mole IDS
something like _when you see a network packet with its source port equal to 31337_
_, fire an alert_. Quite simple, right?

The last part of an IDS are the rules. Each IDS uses its own type of rules, others
share the rule types and that's okay. Mole IDS uses its own rule type, well to be
honest we did not invented the rule type we are using, but it is quite different
from the others. Mole IDS uses [Yara](https://virustotal.github.io/yara/). We have
designed a specific set of metadata for the Yara rules that allows Mole IDS
identifies from which traffic you want to be alerted.
