#! /bin/bash
set -euxo pipefail

# # associate TAP with an actual IP address
ip link set controltap up
ip addr add 172.18.0.0/24 dev controltap
