#!/usr/bin/env bash
set -euo pipefail

mkdir -p /logs/verifier

pip3 install pytest pytest-json-ctrf --quiet --break-system-packages 2>/dev/null || true

# Give Flask a moment to be ready if it just started
for i in $(seq 1 15); do
    curl -sf http://localhost:5000/users > /dev/null 2>&1 && break
    sleep 1
done

if pytest /tests/test_state.py -v \
    --json-report --json-report-file=/logs/verifier/ctrf.json \
    2>&1 | tee /logs/verifier/pytest.log; then
    echo "1.0" > /logs/verifier/reward.txt
else
    echo "0.0" > /logs/verifier/reward.txt
fi
