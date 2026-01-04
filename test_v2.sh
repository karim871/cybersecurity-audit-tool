#!/bin/bash
# Automated testing script for Security Audit Tool v2.0
# Run this to verify all features work correctly

set -e  # Exit on error

TOOL="src/main.py"
REPORT_DIR="reports/tests"
VENV="venv/bin/activate"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}Security Audit Tool v2.0 - Test Suite${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Function to run a test
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_exit="$3"
    
    echo -e "${YELLOW}TEST: ${test_name}${NC}"
    echo "Command: $command"
    
    if eval "$command"; then
        if [ "$expected_exit" == "0" ]; then
            echo -e "${GREEN}✓ PASSED${NC}"
            ((TESTS_PASSED++))
        else
            echo -e "${RED}✗ FAILED (expected failure but succeeded)${NC}"
            ((TESTS_FAILED++))
        fi
    else
        if [ "$expected_exit" == "1" ]; then
            echo -e "${GREEN}✓ PASSED (expected failure)${NC}"
            ((TESTS_PASSED++))
        else
            echo -e "${RED}✗ FAILED${NC}"
            ((TESTS_FAILED++))
        fi
    fi
    echo ""
}

# Activate virtual environment
if [ -f "$VENV" ]; then
    echo -e "${GREEN}✓ Virtual environment found${NC}"
    source "$VENV"
else
    echo -e "${RED}✗ Virtual environment not found at $VENV${NC}"
    echo "Please create one with: python3 -m venv venv"
    exit 1
fi

# Check dependencies
echo -e "${BLUE}Checking dependencies...${NC}"
python -c "import requests, tqdm" 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ All dependencies installed${NC}"
else
    echo -e "${RED}✗ Missing dependencies${NC}"
    echo "Installing..."
    pip install -q requests tqdm
fi
echo ""

# Create report directory
mkdir -p "$REPORT_DIR"

# Test 1: Help flag
run_test "Help flag works" \
    "python $TOOL --help > /dev/null 2>&1" \
    "0"

# Test 2: Version check (basic import)
run_test "Tool can be imported" \
    "python -c 'import sys; sys.path.insert(0, \"src\"); import main' 2>/dev/null" \
    "0"

# Test 3: Invalid target handling
run_test "Invalid hostname error handling" \
    "python $TOOL invalid-host-that-doesnt-exist.local -p 80 2>&1 | grep -q 'ERROR'" \
    "0"

# Test 4: Basic localhost scan
run_test "Basic localhost scan (port 22)" \
    "timeout 30 python $TOOL 127.0.0.1 -p 22 > /dev/null 2>&1" \
    "0"

# Test 5: Verbose flag
run_test "Verbose flag accepted" \
    "timeout 30 python $TOOL 127.0.0.1 -p 22 -v > /dev/null 2>&1" \
    "0"

# Test 6: Port range parsing
run_test "Port range parsing (1-10)" \
    "timeout 30 python $TOOL 127.0.0.1 -p 1-10 > /dev/null 2>&1" \
    "0"

# Test 7: Comma-separated ports
run_test "Comma-separated ports (22,80,443)" \
    "timeout 30 python $TOOL 127.0.0.1 -p 22,80,443 > /dev/null 2>&1" \
    "0"

# Test 8: JSON output
run_test "JSON report generation" \
    "timeout 30 python $TOOL 127.0.0.1 -p 1-100 -o $REPORT_DIR/test_scan.json > /dev/null 2>&1 && [ -f $REPORT_DIR/test_scan.json ]" \
    "0"

# Test 9: Custom timeout
run_test "Custom timeout parameter" \
    "timeout 30 python $TOOL 127.0.0.1 -p 22 -t 0.5 > /dev/null 2>&1" \
    "0"

# Test 10: Custom workers
run_test "Custom workers parameter" \
    "timeout 30 python $TOOL 127.0.0.1 -p 1-50 -w 200 > /dev/null 2>&1" \
    "0"

# Test 11: Combined flags
run_test "Multiple flags combined" \
    "timeout 30 python $TOOL 127.0.0.1 -p 22,80 -v -t 1.0 -w 50 > /dev/null 2>&1" \
    "0"

# Validate JSON output
if [ -f "$REPORT_DIR/test_scan.json" ]; then
    echo -e "${YELLOW}TEST: JSON output validation${NC}"
    if python -m json.tool "$REPORT_DIR/test_scan.json" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASSED - Valid JSON${NC}"
        ((TESTS_PASSED++))
        
        # Check for required fields
        if grep -q '"target"' "$REPORT_DIR/test_scan.json" && \
           grep -q '"scan_time"' "$REPORT_DIR/test_scan.json" && \
           grep -q '"results"' "$REPORT_DIR/test_scan.json"; then
            echo -e "${GREEN}✓ All required fields present${NC}"
        else
            echo -e "${YELLOW}⚠ Some fields missing${NC}"
        fi
    else
        echo -e "${RED}✗ FAILED - Invalid JSON${NC}"
        ((TESTS_FAILED++))
    fi
    echo ""
fi

# Performance test
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}Performance Test${NC}"
echo -e "${BLUE}============================================${NC}"
echo -e "${YELLOW}Scanning 100 ports on localhost...${NC}"

START_TIME=$(date +%s)
timeout 60 python $TOOL 127.0.0.1 -p 1-100 > /dev/null 2>&1
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo -e "${GREEN}Scan completed in ${DURATION} seconds${NC}"

if [ $DURATION -lt 30 ]; then
    echo -e "${GREEN}✓ Performance: Excellent (< 30s)${NC}"
elif [ $DURATION -lt 60 ]; then
    echo -e "${YELLOW}✓ Performance: Good (30-60s)${NC}"
else
    echo -e "${YELLOW}⚠ Performance: Slow (> 60s)${NC}"
fi
echo ""

# Summary
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}============================================${NC}"
echo -e "${GREEN}Tests Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Tests Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed! Your tool is ready to use!${NC}"
    exit 0
else
    echo -e "${RED}⚠ Some tests failed. Please review the output above.${NC}"
    exit 1
fi
