#! /bin/bash
set -euxo pipefail

# delete the ingress queue
tc qdisc del dev eno1 ingress

# (re)create an ingress queue
tc qdisc add dev eno1 handle ffff: ingress

# remove all ingress filters
tc filter del dev eno1 parent ffff:

# mirror ingress traffic with PORT=31415 to mytap interface
tc filter add dev eno1 parent ffff: protocol ip u32 match ip dport 31415 0xffff action mirred egress mirror dev mytap

# delete the TAP ingress queue
tc qdisc del dev mytap ingress

# recreate the TAP ingress queue
tc qdisc add dev mytap handle ffff: ingress

# redirect all outgoing TAP traffic to the NIC
tc filter add dev mytap parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev eno1
