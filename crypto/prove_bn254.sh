#!/bin/zsh

filename="./bench/log.txt"

"" > "$filename"

cargo test --release --package test-circuit --features "parallel print-trace" --lib -- dpp_circuit::dpp_circuit::test_dpp_circuit --exact --show-output >> "$filename"