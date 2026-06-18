#!/bin/bash
# /usr/local/bin/check-audit-health.sh
# Monitor firewall audit trail health and disk usage

set -euo pipefail

AUDIT_DIR="/var/log/firewall-audit"
ALERT_THRESHOLD_PERCENT=80
ALERT_THRESHOLD_GB=10

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

check_audit_path_writable() {
    if [[ ! -d "$AUDIT_DIR" ]]; then
        echo -e "${RED}ERROR${NC}: Audit directory does not exist: $AUDIT_DIR"
        return 1
    fi
    
    if [[ ! -w "$AUDIT_DIR" ]]; then
        echo -e "${RED}ERROR${NC}: Audit directory is not writable: $AUDIT_DIR"
        return 1
    fi
    
    echo -e "${GREEN}OK${NC}: Audit directory exists and is writable"
    return 0
}

check_todays_file() {
    local todays_file="$AUDIT_DIR/audit-$(date -u +%Y-%m-%d).jsonl"
    
    if [[ ! -f "$todays_file" ]]; then
        echo -e "${YELLOW}WARN${NC}: Today's audit file has not been created yet: $todays_file"
        return 0
    fi
    
    local count=$(wc -l < "$todays_file" 2>/dev/null || echo 0)
    echo -e "${GREEN}OK${NC}: Today's audit file exists with $count records"
    return 0
}

check_disk_usage() {
    local usage=$(du -sh "$AUDIT_DIR" 2>/dev/null | awk '{print $1}')
    local usage_bytes=$(du -sb "$AUDIT_DIR" 2>/dev/null | awk '{print $1}')
    local usage_gb=$((usage_bytes / 1024 / 1024 / 1024))
    
    echo "Audit directory disk usage: $usage ($usage_gb GB)"
    
    # Get partition usage percentage
    local partition=$(df "$AUDIT_DIR" | tail -1 | awk '{print $1}')
    local percent=$(df "$AUDIT_DIR" | tail -1 | awk '{print $5}' | sed 's/%//')
    
    if [[ $percent -gt $ALERT_THRESHOLD_PERCENT ]]; then
        echo -e "${RED}ALERT${NC}: Partition $percent% full (threshold: ${ALERT_THRESHOLD_PERCENT}%)"
        return 1
    fi
    
    if [[ $usage_gb -gt $ALERT_THRESHOLD_GB ]]; then
        echo -e "${YELLOW}WARN${NC}: Audit directory $usage_gb GB (threshold: ${ALERT_THRESHOLD_GB} GB)"
        return 0
    fi
    
    echo -e "${GREEN}OK${NC}: Disk usage is healthy"
    return 0
}

check_recent_writes() {
    # Find the most recent audit file
    local latest=$(find "$AUDIT_DIR" -name "audit-*.jsonl*" -type f -printf '%T@ %p\n' | sort -rn | head -1 | awk '{print $2}')
    
    if [[ -z "$latest" ]]; then
        echo -e "${YELLOW}WARN${NC}: No audit files found"
        return 0
    fi
    
    local mtime=$(stat -c %Y "$latest" 2>/dev/null)
    local now=$(date +%s)
    local seconds_ago=$((now - mtime))
    local minutes_ago=$((seconds_ago / 60))
    
    if [[ $seconds_ago -gt 3600 ]]; then
        echo -e "${YELLOW}WARN${NC}: Last write was $minutes_ago minutes ago (check if API is still running)"
        return 0
    fi
    
    echo -e "${GREEN}OK${NC}: Recent audit writes detected ($minutes_ago min ago)"
    return 0
}

check_api_running() {
    if systemctl is-active --quiet opa-api-8001; then
        echo -e "${GREEN}OK${NC}: opa-api-8001 service is running"
        return 0
    else
        echo -e "${RED}ERROR${NC}: opa-api-8001 service is not running"
        return 1
    fi
}

check_api_errors() {
    echo ""
    echo "=== Recent API errors (audit-related) ==="
    journalctl -u opa-api-8001.service --since "1 hour ago" --no-pager | grep -i "audit_store\|permission" | tail -5 || echo "  (none found)"
}

# Main
echo "=== Firewall Audit Trail Health Check ==="
echo ""

check_api_running
check_audit_path_writable
check_todays_file
check_disk_usage
check_recent_writes
check_api_errors

echo ""
echo "=== File List (last 10 days) ==="
find "$AUDIT_DIR" -name "audit-*.jsonl*" -type f -mtime -10 -exec ls -lh {} \; | sort -k6,7 || echo "  (none found)"
