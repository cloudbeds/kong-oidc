#!/bin/bash
set -e

rm -f luacov.stats.out

# Run all test_*.lua files in test/unit
for f in test/unit/test_header_claims.lua; do
  (set -x
    lua -lluacov ${f} -o TAP --failure
  )
done
luacov
cat luacov.report.out
