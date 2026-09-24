#!/bin/bash
# Test all HAETAE security levels
# Ensures all three security levels pass their respective test suites

set -e  # Exit on first error

echo "========================================="
echo "Testing HAETAE Security Levels"
echo "========================================="
echo ""

# Color codes for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Track results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_LEVELS=()

echo -e "${BLUE}[1/3] Testing HAETAE-2 (128-bit security)...${NC}"
echo "Command: cargo test --features haetae2,std --lib"
if cargo test --features haetae2,std --lib 2>&1 | tee /tmp/haetae2_test.log | tail -20; then
    H2_COUNT=$(grep -oP '\d+(?= passed)' /tmp/haetae2_test.log | tail -1)
    echo -e "${GREEN}✓ HAETAE-2: ${H2_COUNT} tests passed${NC}"
    TOTAL_TESTS=$((TOTAL_TESTS + H2_COUNT))
    PASSED_TESTS=$((PASSED_TESTS + H2_COUNT))
else
    echo -e "${RED}✗ HAETAE-2: Tests failed${NC}"
    FAILED_LEVELS+=("HAETAE-2")
fi
echo ""

echo -e "${BLUE}[2/3] Testing HAETAE-3 (192-bit security)...${NC}"
echo "Command: cargo test --no-default-features --features haetae3,std --lib"
if cargo test --no-default-features --features haetae3,std --lib 2>&1 | tee /tmp/haetae3_test.log | tail -20; then
    H3_COUNT=$(grep -oP '\d+(?= passed)' /tmp/haetae3_test.log | tail -1)
    echo -e "${GREEN}✓ HAETAE-3: ${H3_COUNT} tests passed${NC}"
    TOTAL_TESTS=$((TOTAL_TESTS + H3_COUNT))
    PASSED_TESTS=$((PASSED_TESTS + H3_COUNT))
else
    echo -e "${RED}✗ HAETAE-3: Tests failed${NC}"
    FAILED_LEVELS+=("HAETAE-3")
fi
echo ""

echo -e "${BLUE}[3/3] Testing HAETAE-5 (256-bit security)...${NC}"
echo "Command: cargo test --no-default-features --features haetae5,std --lib"
if cargo test --no-default-features --features haetae5,std --lib 2>&1 | tee /tmp/haetae5_test.log | tail -20; then
    H5_COUNT=$(grep -oP '\d+(?= passed)' /tmp/haetae5_test.log | tail -1)
    echo -e "${GREEN}✓ HAETAE-5: ${H5_COUNT} tests passed${NC}"
    TOTAL_TESTS=$((TOTAL_TESTS + H5_COUNT))
    PASSED_TESTS=$((PASSED_TESTS + H5_COUNT))
else
    echo -e "${RED}✗ HAETAE-5: Tests failed${NC}"
    FAILED_LEVELS+=("HAETAE-5")
fi
echo ""

# Summary
echo "========================================="
echo "Test Summary"
echo "========================================="
echo "Total tests passed: ${PASSED_TESTS}/${TOTAL_TESTS}"

if [ ${#FAILED_LEVELS[@]} -eq 0 ]; then
    echo -e "${GREEN}✓ All security levels passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Failed levels: ${FAILED_LEVELS[*]}${NC}"
    exit 1
fi
