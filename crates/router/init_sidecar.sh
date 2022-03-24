#! /bin/bash
set -euxo pipefail

# # associate TAP with an actual IP address
ip link set controltap up
# ip addr add 127.0.1.255/24 dev controltap
# ip addr add 127.0.0.255/24 dev controltap
ip addr add 10.0.1.1/24 dev controltap


# ip link add name loop1 type dummy
# ip addr add 127.0.1.0/24 dev loop1
# ip link set loop1 up
