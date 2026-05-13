#!/bin/bash
# ============================================================
#  servercheck.sh — Comprehensive Server & Domain Checker
#  Rawon Hunter™
# ============================================================

VERSION="1.0.0"

# Colors
R='\033[0;31m' G='\033[0;32m' Y='\033[0;33m'
B='\033[0;34m' C='\033[0;36m' W='\033[1;37m'
DIM='\033[2m' NC='\033[0m'

PASS="${G}✓${NC}" FAIL="${R}✗${NC}" WARN="${Y}!${NC}" INFO="${C}→${NC}"

divider() { echo -e "${DIM}$(printf '─%.0s' {1..65})${NC}"; }
header()  { echo; divider; echo -e "  ${W}$1${NC}"; divider; }

# ============================================================
# 1. SYSTEM INFO
# ============================================================
header "SYSTEM INFO"
HOSTNAME=$(hostname 2>/dev/null)
OS=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)
KERNEL=$(uname -r)
UPTIME=$(uptime -p 2>/dev/null || uptime)
MYIP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
LOCALIP=$(hostname -I | awk '{print $1}')

echo -e "  ${INFO} Hostname   : ${W}${HOSTNAME}${NC}"
echo -e "  ${INFO} OS         : ${OS}"
echo -e "  ${INFO} Kernel     : ${KERNEL}"
echo -e "  ${INFO} Uptime     : ${UPTIME}"
echo -e "  ${INFO} Public IP  : ${W}${MYIP}${NC}"
echo -e "  ${INFO} Local IP   : ${LOCALIP}"

# ============================================================
# 2. DOMAIN DETECTION
# ============================================================
header "DOMAIN DETECTION"

DOMAINS=()

# Apache sites-available & sites-enabled
for DIR in /etc/apache2/sites-enabled /etc/apache2/sites-available \
           /etc/httpd/conf/sites-enabled /etc/httpd/conf.d; do
  if [ -d "$DIR" ]; then
    while IFS= read -r domain; do
      DOMAINS+=("$domain")
    done < <(grep -rh 'ServerName' "$DIR" 2>/dev/null \
      | grep -v '^\s*#' \
      | grep -oE '[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' \
      | grep -v 'example\|localhost\|invalid')
  fi
done

# Nginx
for DIR in /etc/nginx/sites-enabled /etc/nginx/conf.d /etc/nginx/sites-available; do
  if [ -d "$DIR" ]; then
    while IFS= read -r domain; do
      DOMAINS+=("$domain")
    done < <(grep -rh 'server_name' "$DIR" 2>/dev/null \
      | grep -v '^\s*#' \
      | grep -v 'if\s*(' \
      | grep -oE '[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' \
      | grep -v 'example\|localhost\|invalid')
  fi
done

# ISPConfig
for DIR in /usr/local/ispconfig/server/conf /var/ispconfig; do
  [ -d "$DIR" ] && while IFS= read -r domain; do
    DOMAINS+=("$domain")
  done < <(grep -rh 'ServerName\|server_name' "$DIR" 2>/dev/null \
    | grep -v '#' | grep -oE '[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' \
    | grep -v 'example\|localhost')
done

# Docker containers
if command -v docker &>/dev/null; then
  for CID in $(docker ps -q 2>/dev/null); do
    while IFS= read -r domain; do
      DOMAINS+=("$domain")
    done < <(docker exec "$CID" bash -c \
      "grep -rh 'ServerName\|server_name' /etc/apache2/sites-enabled/ /etc/nginx/ 2>/dev/null \
       | grep -v '#' | grep -oE '[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}'" 2>/dev/null \
      | grep -v 'example\|localhost')
  done
fi

# Deduplicate
DOMAINS=($(printf '%s\n' "${DOMAINS[@]}" | sort -u))

echo -e "  ${INFO} Ditemukan ${W}${#DOMAINS[@]}${NC} domain\n"

if [ ${#DOMAINS[@]} -eq 0 ]; then
  echo -e "  ${WARN} Tidak ada domain terdeteksi"
else
  printf "  %-40s %-8s %-6s %-5s %s\n" "DOMAIN" "DNS" "HTTP" "SSL" "EXPIRE"
  divider

  for DOMAIN in "${DOMAINS[@]}"; do
    # DNS check
    RESOLVED=$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | head -1)
    [ -z "$RESOLVED" ] && RESOLVED=$(nslookup "$DOMAIN" 2>/dev/null | grep 'Address:' | tail -1 | awk '{print $2}')

    if [ -z "$RESOLVED" ]; then
      DNS_STATUS="${R}NXDOMAIN${NC}"
    elif [ "$RESOLVED" = "$MYIP" ] || [ "$RESOLVED" = "$LOCALIP" ]; then
      DNS_STATUS="${G}→ server ini${NC}"
    else
      DNS_STATUS="${Y}→ ${RESOLVED}${NC}"
    fi

    # HTTP status
    HTTP_CODE=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "https://${DOMAIN}" 2>/dev/null)
    [ -z "$HTTP_CODE" ] && HTTP_CODE=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "http://${DOMAIN}" 2>/dev/null)
    case "$HTTP_CODE" in
      2*) HTTP_STATUS="${G}${HTTP_CODE}${NC}" ;;
      3*) HTTP_STATUS="${C}${HTTP_CODE}${NC}" ;;
      4*|5*) HTTP_STATUS="${R}${HTTP_CODE}${NC}" ;;
      *) HTTP_STATUS="${DIM}---${NC}" ;;
    esac

    # SSL check
    SSL_EXPIRE=""
    SSL_STATUS="${DIM}N/A${NC}"
    if command -v openssl &>/dev/null; then
      SSL_INFO=$(echo | timeout 5 openssl s_client -servername "$DOMAIN" -connect "${DOMAIN}:443" 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
      if [ -n "$SSL_INFO" ]; then
        EXPIRE_EPOCH=$(date -d "$SSL_INFO" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$SSL_INFO" +%s 2>/dev/null)
        NOW_EPOCH=$(date +%s)
        DAYS_LEFT=$(( (EXPIRE_EPOCH - NOW_EPOCH) / 86400 ))
        if [ "$DAYS_LEFT" -lt 7 ]; then
          SSL_STATUS="${R}KRITIS${NC}"
          SSL_EXPIRE="${R}${DAYS_LEFT}d${NC}"
        elif [ "$DAYS_LEFT" -lt 30 ]; then
          SSL_STATUS="${Y}OK${NC}"
          SSL_EXPIRE="${Y}${DAYS_LEFT}d${NC}"
        else
          SSL_STATUS="${G}OK${NC}"
          SSL_EXPIRE="${G}${DAYS_LEFT}d${NC}"
        fi
      fi
    fi

    printf "  %-40s %-8b %-6b %-5b %b\n" "$DOMAIN" "$DNS_STATUS" "$HTTP_STATUS" "$SSL_STATUS" "$SSL_EXPIRE"
  done
fi

# ============================================================
# 4. RUNNING SERVICES
# ============================================================
header "RUNNING SERVICES"

SERVICES=(nginx apache2 httpd mysql mariadb postgresql php-fpm php8.3-fpm php8.2-fpm php8.1-fpm php7.4-fpm docker fail2ban redis-server memcached)

for SVC in "${SERVICES[@]}"; do
  if systemctl list-units --type=service --all 2>/dev/null | grep -q "^.*${SVC}"; then
    STATUS=$(systemctl is-active "$SVC" 2>/dev/null)
    case "$STATUS" in
      active)   echo -e "  ${PASS} ${SVC}" ;;
      inactive) echo -e "  ${WARN} ${SVC} (inactive)" ;;
      failed)   echo -e "  ${FAIL} ${SVC} (FAILED)" ;;
    esac
  fi
done

# ============================================================
# 5. PHP INFO
# ============================================================
header "PHP"

PHP_BINS=$(update-alternatives --list php 2>/dev/null || find /usr/bin /usr/local/bin -name 'php*' -executable 2>/dev/null | grep -E 'php[0-9.]?$' | sort)
if [ -z "$PHP_BINS" ]; then
  echo -e "  ${FAIL} PHP tidak terinstall"
else
  echo "$PHP_BINS" | while read -r phpbin; do
    VER=$("$phpbin" -v 2>/dev/null | head -1 | awk '{print $2}')
    echo -e "  ${PASS} $phpbin — v${VER}"
  done
fi

# PHP-FPM sockets
SOCKS=$(ls /run/php/*.sock 2>/dev/null)
if [ -n "$SOCKS" ]; then
  echo -e "  ${INFO} FPM sockets:"
  echo "$SOCKS" | while read -r s; do echo -e "    ${DIM}${s}${NC}"; done
fi

# ============================================================
# 6. DATABASE
# ============================================================
header "DATABASE"

# MySQL / MariaDB
if command -v mysql &>/dev/null; then
  if mysql -e "SELECT 1" &>/dev/null 2>&1; then
    DB_SIZE=$(mysql -e "SELECT ROUND(SUM(data_length+index_length)/1024/1024,1) FROM information_schema.tables;" 2>/dev/null | tail -1)
    DB_COUNT=$(mysql -e "SHOW DATABASES;" 2>/dev/null | grep -v Database | wc -l)
    echo -e "  ${PASS} MySQL/MariaDB — running"
    echo -e "  ${INFO} Databases : ${DB_COUNT} | Total size: ${DB_SIZE}MB"
  else
    echo -e "  ${WARN} MySQL/MariaDB — tidak bisa connect (mungkin butuh password)"
  fi
else
  echo -e "  ${DIM}MySQL tidak terinstall${NC}"
fi

# PostgreSQL
if command -v psql &>/dev/null; then
  if sudo -u postgres psql -c "SELECT 1" &>/dev/null 2>&1; then
    PG_LIST=$(sudo -u postgres psql -t -c "SELECT datname, pg_size_pretty(pg_database_size(datname)) FROM pg_database ORDER BY pg_database_size(datname) DESC;" 2>/dev/null)
    echo -e "  ${PASS} PostgreSQL — running"
    echo "$PG_LIST" | grep -v '^\s*$' | while read -r line; do
      echo -e "    ${DIM}${line}${NC}"
    done
  else
    echo -e "  ${WARN} PostgreSQL — tidak bisa connect"
  fi
else
  echo -e "  ${DIM}PostgreSQL tidak terinstall${NC}"
fi

# ============================================================
# 7. DOCKER
# ============================================================
if command -v docker &>/dev/null; then
  header "DOCKER"
  RUNNING=$(docker ps -q 2>/dev/null | wc -l)
  TOTAL=$(docker ps -aq 2>/dev/null | wc -l)
  echo -e "  ${INFO} Containers: ${G}${RUNNING} running${NC} / ${TOTAL} total"
  echo

  docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | while read -r line; do
    echo -e "  ${DIM}${line}${NC}"
  done
fi

# ============================================================
# 8. SECURITY
# ============================================================
header "SECURITY"

# Fail2ban
if systemctl is-active fail2ban &>/dev/null; then
  BANNED=$(fail2ban-client status sshd 2>/dev/null | grep 'Banned IP' | grep -oE '[0-9]+' | tail -1)
  echo -e "  ${PASS} Fail2ban aktif — ${BANNED:-0} IP banned (SSH)"
else
  echo -e "  ${WARN} Fail2ban tidak aktif"
fi

# SSH config
SSH_PORT=$(grep -E '^Port\s' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
PASS_AUTH=$(grep -E '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
ROOT_LOGIN=$(grep -E '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
echo -e "  ${INFO} SSH port          : ${SSH_PORT:-22}"
[ "$PASS_AUTH" = "yes" ] && echo -e "  ${WARN} PasswordAuth      : yes (pertimbangkan disable)" || echo -e "  ${PASS} PasswordAuth      : ${PASS_AUTH:-default}"
[ "$ROOT_LOGIN" = "yes" ] && echo -e "  ${WARN} PermitRootLogin   : yes" || echo -e "  ${PASS} PermitRootLogin   : ${ROOT_LOGIN:-default}"

# Open ports
echo -e "\n  ${INFO} Open ports (listening):"
ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | grep -oE '[0-9]+$' | sort -n | uniq | tr '\n' ' '
echo

# ============================================================
# 9. WEB ROOT LOCATIONS
# ============================================================
header "WEB ROOT LOCATIONS"

# Apache / httpd
for DIR in /etc/apache2/sites-enabled /etc/httpd/conf/sites-enabled /etc/httpd/conf.d; do
  [ -d "$DIR" ] || continue
  grep -rh 'ServerName\|DocumentRoot' "$DIR" 2>/dev/null | grep -v '^\s*#' | while read -r line; do
    if echo "$line" | grep -qi 'ServerName'; then
      CURRENT_DOMAIN=$(echo "$line" | grep -oE '[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' | head -1)
    elif echo "$line" | grep -qi 'DocumentRoot'; then
      DOCROOT=$(echo "$line" | awk '{print $2}' | tr -d '"')
      [ -n "$CURRENT_DOMAIN" ] && [ -n "$DOCROOT" ] && \
        printf "  ${INFO} %-40s ${DIM}%s${NC}\n" "$CURRENT_DOMAIN" "$DOCROOT"
    fi
  done
done

# Nginx
for DIR in /etc/nginx/sites-enabled /etc/nginx/conf.d; do
  [ -d "$DIR" ] || continue
  for CONF in "$DIR"/*.conf "$DIR"/*; do
    [ -f "$CONF" ] || continue
    CURRENT_DOMAIN=""
    while IFS= read -r line; do
      if echo "$line" | grep -q 'server_name' && ! echo "$line" | grep -q 'if\s*('; then
        CURRENT_DOMAIN=$(echo "$line" | grep -oE '[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' | head -1)
      elif echo "$line" | grep -q '^\s*root\s'; then
        DOCROOT=$(echo "$line" | awk '{print $2}' | tr -d ';')
        [ -n "$CURRENT_DOMAIN" ] && [ -n "$DOCROOT" ] && \
          printf "  ${INFO} %-40s ${DIM}%s${NC}\n" "$CURRENT_DOMAIN" "$DOCROOT"
      elif echo "$line" | grep -q 'proxy_pass'; then
        PROXY=$(echo "$line" | awk '{print $2}' | tr -d ';')
        [ -n "$CURRENT_DOMAIN" ] && [ -n "$PROXY" ] && \
          printf "  ${INFO} %-40s ${DIM}→ proxy: %s${NC}\n" "$CURRENT_DOMAIN" "$PROXY"
        CURRENT_DOMAIN=""
      fi
    done < "$CONF"
  done
done

# Docker containers web roots
if command -v docker &>/dev/null; then
  for CID in $(docker ps -q 2>/dev/null); do
    CNAME=$(docker inspect --format '{{.Name}}' "$CID" | tr -d '/')
    DOMAIN=$(docker exec "$CID" bash -c \
      "grep -rh 'ServerName\|server_name' /etc/apache2/sites-enabled/ /etc/nginx/ 2>/dev/null \
       | grep -v '#' | grep -oE '[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' | head -1" 2>/dev/null)
    DOCROOT=$(docker exec "$CID" bash -c \
      "grep -rh 'DocumentRoot\|^\s*root\s' /etc/apache2/sites-enabled/ /etc/nginx/ 2>/dev/null \
       | grep -v '#' | awk '{print \$2}' | tr -d ';\042' | head -1" 2>/dev/null)
    [ -n "$DOMAIN" ] && printf "  ${INFO} %-40s ${DIM}[docker: %s] %s${NC}\n" "$DOMAIN" "$CNAME" "${DOCROOT:-N/A}"
  done
fi

# ============================================================
# SUMMARY
# ============================================================
header "SUMMARY"
echo -e "  ${INFO} Script    : servercheck.sh v${VERSION} by Rawon Hunter™"
echo -e "  ${INFO} Domains   : ${#DOMAINS[@]} terdeteksi"
echo -e "  ${INFO} Disk      : $(df -h / | awk 'NR==2{print $5}') used on /"
echo
