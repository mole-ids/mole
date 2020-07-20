# Quick Start

Catch It Now
{: .subtitle }

First of all you need a copy of Mole IDS and a Linux box. At the moment we only
provide you with the source files so you will have to compile Mole IDS by your own.
However, we eased that process as much as we could. Please go to
[Install-Mole](/getting-started/install-mole/) to install Mole IDS.

Once you have Mole IDS installed you are ready to capture traffic. You must run
Mole IDS as `root` using the following command:

```shell
./mole ids --iface <iface> --rulesDir <path>
```

In the previous command you need to adjust the interface where the traffic will
come into Mole IDS and a Yara rules directory.

Mole will log everything in the console and you can imagine that is not really
handy, thus you can provide some arguments to change that behaviour. You must know
that Mole IDS has two types of logs, the first one is for logging the application
messages and the second one is for logging the events triggered by the rules.

```shell
./mole ids --iface <iface> --rulesDir <path> --logTo <file> --moleLogTo <file>
```

In the previous command `--logTo` is used to log Mole IDS events and `--moleLogTo`
is used to log the alerts based on the rules.
