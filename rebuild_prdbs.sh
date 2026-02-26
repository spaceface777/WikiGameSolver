#!/usr/bin/env bash
set -u

base_url="https://github.com/spaceface777/WikiGameSolver/releases/latest/download"
out_dir="prdumps"

mkdir -p "$out_dir"

langs=( en fr de ja it ru es zh pl nl pt ar fi hu th he tr sv el fa )

for lang in "${langs[@]}"; do
  echo "==> $lang"
  if ! curl -fsSL "${base_url}/${lang}.bin" | ./cli --db - --dump-pagerank "${out_dir}/${lang}.prdb"; then
    echo "!! failed: $lang" >&2
  fi
done
