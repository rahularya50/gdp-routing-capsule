#! /bin/bash
set -euxo pipefail

# # associate TAP with an actual IP address
ip link set controltap up
ip addr add 192.168.0.250/24 dev controltap
