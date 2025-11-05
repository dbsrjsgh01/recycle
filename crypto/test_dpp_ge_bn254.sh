#!/bin/bash

filename="./bench/dpp_circuit_log.txt"

"" > "$filename"

cargo test --release --package test-circuit --features "parallel print-trace" --lib -- dpp_circuit::dpp_circuit::test_cp_dpp_bn254 --exact --show-output >> "$filename"
