# Configuration Introduction

How the Magic Happens
{: .subtitle }

Mole IDS can be configured issuing arguments when you execute Mole IDS form the
command line. But, you can also use a configuration file, which will make your
life a little bit easy.

Mole IDS uses a `YAML` file to define its options and it is called `mole.yml`.
`mole.yml` can be placed next to the Mole IDS binary or in `/etc/mole/mole.yml`.
Although, you can also define the `mole.yml` location using the command line
flag `--config <path>`.

!!! example "Mole IDS configuration falg"

  ```shell
    ./mole --config <path_to_mole.yml> ids --iface ens33
  ```

At the moment the configuration file is splited up in four sections:

* interface: Configuration related to the interface.
* engine: Configuration related to the engine.
* rules: Rules related options.
* logger: logger configurations.

## Interface

The interface section indicates which interface will be used by Mole IDS, if the
want to use PF_RING features or you can define a BPF filter.

```yaml
interface:
    iface: ens33
    pf_ring: true
    bpf: udp and dst port not 53
```

On the previous example Mole will listen traffic from the `ens33` interface.
PF_RING will be used as capturing driver and only the traffic defined in the
`bpf` filter will be captured.

When setting `interface.pf_ring` to `false` Mole IDS will use libpcap to capture
packages from the interface.

If Mole IDS was compiled without PF_Ring support and you configure it to use
the PF_Ring driver, Mole IDS will fall down to libpcap.

## engine

The engine sections has no options at the moment, this section is defined for
future purposes.

## rules

This section defines where and how the Yara rules should be loaded. In this secction
we defined two entry for loading the rules, one for loading them from a directory
so Mole IDS will load all `*.yar` files in that folder without recursion. Second,
you can provide a Yara rules index file and Mole will load those rules. Moreover,
there is a section for the user to define a set of variables. Those variables can
be used later on in the rules.

```yaml
rules:
    rules_dir: ./rules
    rules_index: ./index.yar
    variables:
      $HOME_NET: "10.0.0.0/8"
```

If you are wondering yourself how to use the variables, I'll show you down below,
but if you want to know more about rules, pleae go to
[writing rules](/writing-rules/) section.

```yara
rule ExampleRule {
    meta:
        type = "alert"
        proto = "tcp"
        src = "$HOME_NET"
        sport = "any"
        dst = "any"
        sport = "80"

    strings:
        $host = "google.com"

    condition:
        $host
}
```

## logger

Finally, we defined a logging section. This section defines two types of logger,
the first one is for Mole IDS where Mole IDS will log all the internal messages,
on the other hand, the sencod type of log is for the Mole IDS users. That log will
contain a `JSON` object with the matching alert information.

```yaml
logger:
    log_to: /dev/stdout
    log_level: "info"

    mole:
      format: eve
      to: /var/log/mole/alert.json
```

`log_to` and `log_level` indicates to Mole IDS where and in which level should log
the internal stuff. On th other hand, there is a `mole` entry where the alert logs
are defined. `mole.format` is used to output the alerts in different formats and
`mole.to` indicates where Mole IDS will write the alerts.

!!! warning
    At the moment there is one unique format avaliable, which is `eve`. That format
    writes the logs in `JSON` format, but the content of the logs mimics the
    `eve.json` format from [Suticata IDS](https://suricata-ids.org/).

Following there is an example of an alert output.

```json
{
  "level": "info",
  "ts": 1594760683.2996953,
  "msg": "mole",
  "mole_event": {
    "timestamp": "2020-07-14T23:04:42.919469+0200",
    "event_type": "alert",
    "in_iface": "ens33",
    "src_ip": "172.16.150.208/32",
    "src_port": 6009,
    "dst_ip": "216.58.211.46/32",
    "dst_port": 80,
    "proto": "tcp",
    "alert": {
      "name": "HTTPGetGoogle",
      "id": "",
      "tags": [
        "tcp",
        "http"
      ],
      "meta": {
        "description": "Detect http get method to google.com",
        "type": "alert",
        "proto": "tcp",
        "src": "172.16.0.0/16",
        "sport": "0:65535",
        "dst": "0.0.0.0/0",
        "dport": "80"
      }
    },
    "matches": [
      {
        "name": "$method",
        "data": "R0VU",
        "base": 0,
        "offset": 0
      },
      {
        "name": "$host",
        "data": "Z29vZ2xlLmNvbQ==",
        "base": 0,
        "offset": 22
      }
    ]
  }
}
```

## Full example

```yaml
interface:
    iface: ens33
    pf_ring: true
    bpf: udp and dst port not 53

engine:

rules:
    rules_dir: ./rules
    rules_index: ./index.yar
    variables:
      $HOME_NET: "10.0.0.0/8"

logger:
    log_to: /dev/stdout
    log_level: "info"

    mole:
      format: eve
      to: /var/log/mole/alert.json
```
