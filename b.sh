#!/bin/bash

./target/release/rb-node benchmark \
    --chain=local \
    --execution=wasm \
    --wasm-execution=compiled \
    --pallet=pallet_randomness_beacon \
    --extrinsic "*" \
    --repeat 20 \
