#!/bin/bash
# Example usage scripts for Security Audit Tool v2.0

echo "Security Audit Tool v2.0 - Example Scripts"
echo "==========================================="
echo ""

# Ensure we're in the project directory
cd "$(dirname "$0")/.." || exit 1

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Example 1: Basic localhost scan
echo "Example 1: Basic localhost scan (ports 1-100)"
echo "Command: python src/main.py 127.0.0.1 -p 1-100"
echo ""
read -p "Press Enter to run..."
python src/main.py 127.0.0.1 -p 1-100
echo ""

# Example 2: Verbose scan with specific ports
echo "Example 2: Verbose scan of common ports"
echo "Command: python src/main.py 127.0.0.1 -p 22,80,443,3306,8080 -v"
echo ""
read -p "Press Enter to run..."
python src/main.py 127.0.0.1 -p 22,80,443,3306,8080 -v
echo ""

# Example 3: Fast scan with more workers
echo "Example 3: Fast scan (ports 1-1000 with 200 workers)"
echo "Command: python src/main.py 127.0.0.1 -p 1-1000 -w 200"
echo ""
read -p "Press Enter to run..."
python src/main.py 127.0.0.1 -p 1-1000 -w 200
echo ""

# Example 4: Scan with JSON report
echo "Example 4: Scan with JSON report output"
echo "Command: python src/main.py 127.0.0.1 -p 1-500 -o reports/example_scan.json"
echo ""
read -p "Press Enter to run..."
python src/main.py 127.0.0.1 -p 1-500 -o reports/example_scan.json
echo ""
echo "Report saved! View with: cat reports/example_scan.json | jq"
echo ""

# Example 5: Custom timeout
echo "Example 5: Slower, more accurate scan"
echo "Command: python src/main.py 127.0.0.1 -p 1-100 -t 2.0"
echo ""
read -p "Press Enter to run..."
python src/main.py 127.0.0.1 -p 1-100 -t 2.0
echo ""

echo "==========================================="
echo "All examples completed!"
echo ""
echo "Try these commands yourself:"
echo "  python src/main.py 127.0.0.1 -p 1-1000 -v"
echo "  python src/main.py 127.0.0.1 -p 1-65535 -w 500 -o full_scan.json"
echo ""
echo "Run tests with:"
echo "  python tests/test_suite.py"
echo ""
