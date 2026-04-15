#!/usr/bin/env bash
set -euo pipefail

mkdir -p /logs/verifier

pip3 install pytest pytest-json-ctrf --quiet --break-system-packages 2>/dev/null || true

if pytest /tests/test_state.py -v \
    --ctrf /logs/verifier/ctrf.json \
    2>&1 | tee /logs/verifier/pytest.log; then
    echo "1.0" > /logs/verifier/reward.txt
else
    echo "0.0" > /logs/verifier/reward.txt
fi
