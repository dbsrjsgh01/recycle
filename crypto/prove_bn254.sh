#!/bin/zsh

filename="./bench/log.txt"

"" > "$filename"

cargo test --release --package test-circuit --features "parallel print-trace" --lib -- circuit::circuit::test_circuit --exact --show-output >> "$filename"