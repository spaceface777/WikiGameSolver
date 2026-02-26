#!/usr/bin/env bash
set -euo pipefail

base="https://github.com/spaceface777/WikiGameSolver/releases/latest/download"
out="prdumps"
mkdir -p "$out"

langs='en fr de ja it ru es zh pl nl pt ar fi hu th he tr sv el fa'

parallel -j3 --tag --line-buffer --halt never \
  'curl -fsSL '"$base"'/{1}.bin | ./cli --db - --dump-pagerank '"$out"'/{1}.prdb' \
  ::: $langs
