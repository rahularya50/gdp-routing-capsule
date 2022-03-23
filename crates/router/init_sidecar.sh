#! /bin/bash
set -euxo pipefail

# associate TAP with an actual IP address
ip link set controltap up
ip addr add 127.0.0.2/32 dev controltap
