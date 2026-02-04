#!/bin/bash
# Demo scenarios for screenshots

echo "=== Scenario 1: Basic Scan with Progress ==="
python src/main.py 127.0.0.1 -p 1-100 -v

echo ""
echo "=== Scenario 2: Fast Scan (500 workers) ==="
python src/main.py 127.0.0.1 -p 1-500 -w 500

echo ""
echo "=== Scenario 3: Vulnerability Detection ==="
# Start a test FTP server (intentionally vulnerable)
# We'll use nc to simulate services
echo "Simulating vulnerable services..."
python src/main.py 127.0.0.1 -p 20-25,80,443,3306 -v

echo ""
echo "=== Scenario 4: Report Generation ==="
python src/main.py 127.0.0.1 -p 1-1000 -o reports/demo_scan.json
cat reports/demo_scan.json | head -20

