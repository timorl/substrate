#!/bin/bash

killall -9 rb-node

set -e

clear


cargo +nightly-2020-08-23 build -p rb-node

./target/debug/rb-node purge-chain --base-path /tmp/alice --chain local -y
./target/debug/rb-node purge-chain --base-path /tmp/bob --chain local -y
./target/debug/rb-node purge-chain --base-path /tmp/charlie --chain local -y
./target/debug/rb-node purge-chain --base-path /tmp/dave --chain local -y

cnf="--validator --chain local"

./target/debug/rb-node $cnf --base-path /tmp/alice   --alice   --ws-port 9944 --port 30334 --rpc-port 9934 --execution Native 2> alice.log   &
./target/debug/rb-node $cnf --base-path /tmp/bob     --bob     --ws-port 9945 --port 30335 --rpc-port 9935 --execution Native 2> bob.log     &
./target/debug/rb-node $cnf --base-path /tmp/charlie --charlie --ws-port 9946 --port 30336 --rpc-port 9936 --execution Native 2> charlie.log &
./target/debug/rb-node $cnf --base-path /tmp/dave    --dave    --ws-port 9947 --port 30337 --rpc-port 9937 --execution Native 2> dave.log    &
