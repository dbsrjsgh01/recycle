#!/bin/bash

filename="./bench/trade_circuit_log.txt"

"" > "$filename"

cargo test -r --package test-circuit --lib --features "parallel print-trace" -- encryption::trade_circuit::trade_circuit::test_cp_trade_bn254 --show-output >> "$filename"
