# Generating a firewall

A complete, generated firewall requires several JSON configuration
sections. These can either be compiled into one long JSON file or split
into separate files. An example usable firewall has been included within
this gem's `examples/policy` directory.

# Example JSON configuration files

## macros.json

This file defines macros, which are reusable rules or sets of rules.
Each macro consists of an identifier (example `accept-established`), and
its expansion. For more on rules, see section `Rules`.

## policy.json

This file defines policy, which is the "top-level" configuration
for your **desired** iptables rules. 

Assuming you are using configuration-management software such as
[http://www.opscode.com/chef](Chef), you can set one policy for all of
your hosts, and then customize your policy per host using rules (see
`rules.json`) and primitives (see `primitives.json`).

The policy file is a hash of the four "standard" iptables tables:
`filter`, `mangle`, `nat`, and `raw`. Each of these can in turn either
be a hash configuring the table, or `null`. 

### `null`

If `null`, the policy for that table will be "whatever is already
defined". For example, the example configuration file shows 
`"mangle": null`, which means: "if there is a `mangle` table, use its
rules, otherwise leave this table undefined".

### hash

If a hash, the table must contain a hash of table names. These will be
the standard tables for the corresponding iptables table. For instance,
`filter` should minimally contain `INPUT`, `FORWARD`, and `OUTPUT`.
Other user-defined tables may also be defined/named.

Each defined table must have a `policy`. This can either be `DROP`,
`ACCEPT`, or `-`.

Each defined table must also have a `rules` section. This must be an
array of firewall rules. For more on rules, see section `Rules`.

## policy6.json

This is the same as `policy.json`, but defines ipv6 rules.

## primitives.json

Primitives are values that can be interpolated into other parts of your
firewall. For more on how these interpolations are used, see section
`Interpolation`.

## rules.json

`rules` can be an empty hash, or contain any of the named iptables
tables (`filter`, `nat`, etc). Any named table is **added** to the rules
defined by policy (see example `policy.json`).

If a table is **not** found in policy, it is added to the generated
firewall. It is advised to define at least all standard chains for the
table. For instance, `nat` should minimally contain `INPUT`, `OUTPUT`,
`POSTROUTING` and `PREROUTING`, and each of these should minimally
contain a `policy` definition.

If a table **is** found in policy, each specified chain can either
override or modify the existing table within the policy. 

### Overriding Chain Policy

Set `"policy": "ACCEPT"` or any other valid policy.

### Overriding Chain Rules

Set `"rules": []`. In this case, rules will be reset to be empty.
Alternately, fill the array with rules (see section `Rules`).

### Adding Chain Rules

Set `"additions": []`. Rules (see section `Rules`) added into this array
will be added at node addition points within the policy rules (see
section `additions`).

## services.json

This file defines services that you will be using within your firewall.
See section `Rules` on how to define each service.

Once defined, a service may be used within policy, rules, or macros.

# Rules

Rules fall within an array, and can consist of strings or hashes.

## String Rules

A policy that is a string is inserted as-is into the policy
firewall, preceded by `-A the_chain_name`. A very simple firewall could
consist solely of string rules.

## Hash rules

Other kinds of rules are defined as hashes, with the hash key denoting
the type of rule:

### `comment`

This is shorthand for an iptables comment:

    "comment": "comment1"

becomes

    -A chain_name -m comment --comment "comment1"

The `chain_name` is the name of the chain in which the `comment` rule is
found.

### `interpolated`

See section "Interpolating strings"

### `macro`

This inserts the requested macro (see section `macros.json`) into the
rules.

### `node_addition_points`

See section "`additions` and `node_addition_points`"

### `service`

This inserts the requested service (see section `services.json`) into
the rules.

### `service_tcp`

This takes an integer or string as an argument and inserts a permitted
inbound TCP port into the rules:

    "service_tcp": 8080

becomes

    -A chain_name -p tcp -m tcp --sport 1024:65535 --dport 8080 -m state --state NEW,ESTABLISHED -j ACCEPT

Port ranges such as `"8080:8090"` can also be used. The `chain_name` is
the name of the chain in which the `service_tcp` rule is found.

### `service_udp`

This is identical to `service_tcp`, except that it inserts a permitted
inbound UDP port.

### `ulog`

This is shorthand for an iptables logging statement:

    "ulog": ""

becomes

    -A chain_name -m limit --limit 1/sec --limit-burst 2 -j ULOG --ulog-prefix "chain_name:"

This can also use `-p tcp`:

    "ulog": "-p tcp"

becomes

    -A chain_name -p tcp -m limit --limit 1/sec --limit-burst 2 -j ULOG --ulog-prefix "chain_name:"

The `chain_name` is the name of the chain in which the `ulog` rule is
found.

# Interpolation

Primitives (see section `primitives.json`) are available within your
configuration using the `<%%>` notation within an `interpolated` rule.

## Interpolating strings

An example usage is:

     "interpolated": "-s <% internet.subnet.other %> -d <% internet.address %> -i <% internet.device %> -j ACCEPT"

Depending upon the defined primitives, the above rule could expand into:

     -s 192.0.2.0/24 -d 198.51.100.10/32 -i eth0 -j ACCEPT

## Interpolating arrays

Primitives that are defined as an array, such as `iana_reserved` in the
example `primitives.json`, will expand into multiple rules. For instance

     "interpolated": "-s <% iana_reserved %> -j DROP"

would expand into

    -s 0.0.0.0/8 -j DROP
    -s 5.0.0.0/8 -j DROP
    -s 10.0.0.0/8 -j DROP
    -s 36.0.0.0/7 -j DROP
    -s 39.0.0.0/8 -j DROP
    -s 42.0.0.0/8 -j DROP
    -s 49.0.0.0/8 -j DROP
    -s 100.0.0.0/6 -j DROP
    -s 104.0.0.0/7 -j DROP
    -s 106.0.0.0/8 -j DROP
    -s 127.0.0.0/8 -j DROP
    -s 179.0.0.0/8 -j DROP
    -s 185.0.0.0/8 -j DROP
    -s 240.0.0.0/4 -j DROP
    -s 169.254.0.0/16 -j DROP
    -s 172.16.0.0/12 -j DROP
    -s 192.0.2.0/24 -j DROP
    -s 192.88.99.0/24 -j DROP
    -s 192.168.0.0/16 -j DROP


# `additions` and `node_addition_points`

Since adding rules to a policy firewall is very common, there is a
shorthand for adding rules to one or more policy chains at predefined
points.

For instance, you may define the following policy (see `Rules`):

    "policy": {
      (other chains)
      "in_public": {
        "policy": "ACCEPT",
        "rules": {
          { "comment": "comment1" },
          {
            "node_addition_points": [
              "in_public",
              "in_*"
            ]
          }
          { "comment": "comment2" },
        }
      }
    }

You may then also choose to define the following rules:

    "rules": {
      "filter": {
        "in_public": {
          "additions": [
            "comment": "public"
          ]
        },
        "in_*": {
          "additions": [
            "comment": "all"
          ]
        }
      }
    }

The `rules` defined within the `in_public` chain or `in_*`
pseudo-chain would be added at the `node_addition_points` within the
table. So the generated firewall would contain:

    -A in_public -m comment --comment "comment1"
    -A in_public -m comment --comment "public"
    -A in_public -m comment --comment "all"
    -A in_public -m comment --comment "comment2"

