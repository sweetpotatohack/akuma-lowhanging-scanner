#!/bin/bash

# ========================================================================
# AKUMA'S IMPROVEMENT TESTER - Быстрая проверка исправлений
# ========================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${RED}🔥 TESTING SCANNER IMPROVEMENTS 🔥${NC}"
echo ""

# Тестируем конкретные хосты с известными результатами
TEST_HOSTS=(
    "192.168.112.156"  # SMBGhost vulnerable  
    "192.168.112.197"  # SMBGhost vulnerable
    "192.168.112.237"  # SMBGhost vulnerable
    "192.168.112.59"   # Not vulnerable
)

RESULTS_DIR="/tmp/improvement_test_$(date +%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo -e "${CYAN}Testing improved vulnerability detection...${NC}"

# Тест 1: SMBGhost detection с новым паттерном
echo -e "${YELLOW}[TEST 1] SMBGhost Detection${NC}"
for host in "${TEST_HOSTS[@]}"; do
    echo -n "Testing $host: "
    
    nxc_output=$(timeout 30 nxc smb "$host" -M smbghost 2>/dev/null)
    
    # Новый улучшенный паттерн
    if echo "$nxc_output" | grep -qi "vulnerable\|potentially vulnerable\|smbghost.*vulnerable\|cve-2020-0796"; then
        echo -e "${RED}VULNERABLE${NC}"
        echo "$host - SMBGhost VULNERABLE" >> "$RESULTS_DIR/vulnerabilities.txt"
    else
        echo -e "${GREEN}Not vulnerable${NC}"
    fi
done

echo ""

# Тест 2: MS17-010 detection
echo -e "${YELLOW}[TEST 2] MS17-010 Detection${NC}"
for host in "${TEST_HOSTS[@]}"; do
    echo -n "Testing $host: "
    
    nxc_output=$(timeout 30 nxc smb "$host" -M ms17-010 2>/dev/null)
    
    # Улучшенный паттерн для MS17-010
    if echo "$nxc_output" | grep -qi "vulnerable\|ms17-010.*vulnerable\|eternalblue"; then
        echo -e "${RED}VULNERABLE${NC}"
        echo "$host - MS17-010 VULNERABLE" >> "$RESULTS_DIR/vulnerabilities.txt"
    else
        echo -e "${GREEN}Not vulnerable${NC}"
    fi
done

echo ""

# Тест 3: General host info
echo -e "${YELLOW}[TEST 3] Host Information${NC}"
for host in "${TEST_HOSTS[@]}"; do
    echo -e "${CYAN}Host: $host${NC}"
    timeout 15 nxc smb "$host" 2>/dev/null | grep -E "(Windows|Build|domain|signing)" | head -1
    echo ""
done

# Результаты
echo -e "${GREEN}=== TEST RESULTS ===${NC}"
if [[ -f "$RESULTS_DIR/vulnerabilities.txt" ]]; then
    echo -e "${RED}VULNERABILITIES DETECTED:${NC}"
    cat "$RESULTS_DIR/vulnerabilities.txt"
else
    echo "No vulnerabilities detected with current patterns"
fi

echo ""
echo "Test results saved to: $RESULTS_DIR"

# Предлагаем запустить полный сканер для сравнения
echo ""
echo -e "${CYAN}Run full scanner test? (y/n)${NC}"
read -r response
if [[ $response =~ ^[Yy]$ ]]; then
    echo "Running improved scanner on test subset..."
    
    # Создаём тестовый конфиг
    cat > "$RESULTS_DIR/test_config.conf" << EOF
SUBNETS=(
    "192.168.112.156/32"
    "192.168.112.197/32"
    "192.168.112.237/32"
)
MAX_PARALLEL=5
TIMEOUT_PER_HOST=60
DEBUG_MODE=true
EOF

    ./advanced_lowhanging_scanner.sh --config "$RESULTS_DIR/test_config.conf"
fi
