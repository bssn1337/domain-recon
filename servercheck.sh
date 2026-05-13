#!/bin/bash
# ============================================================
#  servercheck.sh — Modular Server & Domain Checker
#  Rawon Hunter™ | github.com/bssn1337/domain-recon
# ============================================================

VERSION="2.1.0"

R='\033[0;31m' G='\033[0;32m' Y='\033[0;33m'
C='\033[0;36m' W='\033[1;37m' DIM='\033[2m' NC='\033[0m'
PASS="${G}✓${NC}" FAIL="${R}✗${NC}" WARN="${Y}!${NC}" INFO="${C}→${NC}"

divider() { echo -e "${DIM}$(printf '─%.0s' {1..65})${NC}"; }
header()  { echo; divider; echo -e "  ${W}$1${NC}"; divider; }

DOMAINS=()
WEB_ENGINE=""

# ============================================================
# DETECT: Web server engine yang aktif
# ============================================================
detect_engine() {
  header "WEB ENGINE DETECTION"

  # Urutan prioritas deteksi
  if systemctl is-active --quiet lsws 2>/dev/null || \
     pgrep -x litespeed &>/dev/null || pgrep -x lshttpd &>/dev/null; then
    WEB_ENGINE="openlitespeed"
    echo -e "  ${PASS} Terdeteksi: ${W}OpenLiteSpeed${NC}"

  elif [ -d /usr/local/cpanel ] || command -v whmapi1 &>/dev/null || \
       [ -f /etc/cpanel/cpanel.config ]; then
    WEB_ENGINE="cpanel"
    echo -e "  ${PASS} Terdeteksi: ${W}cPanel/WHM${NC}"
    # cPanel pakai Apache di balik
    if systemctl is-active --quiet httpd 2>/dev/null || \
       systemctl is-active --quiet apache2 2>/dev/null; then
      echo -e "  ${INFO} Web server  : Apache (via cPanel)"
    fi

  elif [ -d /usr/local/directadmin ] || command -v directadmin &>/dev/null; then
    WEB_ENGINE="directadmin"
    echo -e "  ${PASS} Terdeteksi: ${W}DirectAdmin${NC}"

  elif [ -d /usr/local/ispconfig ] || [ -f /usr/local/ispconfig/server/lib/config.inc.php ]; then
    WEB_ENGINE="ispconfig"
    echo -e "  ${PASS} Terdeteksi: ${W}ISPConfig${NC}"

  elif [ -d /usr/local/plesk ] || command -v plesk &>/dev/null; then
    WEB_ENGINE="plesk"
    echo -e "  ${PASS} Terdeteksi: ${W}Plesk${NC}"

  elif systemctl is-active --quiet nginx 2>/dev/null || \
       pgrep -x nginx &>/dev/null; then
    # Nginx bisa jadi standalone atau reverse proxy Apache
    if systemctl is-active --quiet apache2 2>/dev/null || \
       systemctl is-active --quiet httpd 2>/dev/null; then
      WEB_ENGINE="nginx+apache"
      echo -e "  ${PASS} Terdeteksi: ${W}Nginx + Apache${NC} (Nginx sebagai reverse proxy)"
    else
      WEB_ENGINE="nginx"
      echo -e "  ${PASS} Terdeteksi: ${W}Nginx${NC}"
    fi

  elif systemctl is-active --quiet apache2 2>/dev/null || \
       systemctl is-active --quiet httpd 2>/dev/null || \
       pgrep -x apache2 &>/dev/null || pgrep -x httpd &>/dev/null; then
    WEB_ENGINE="apache"
    echo -e "  ${PASS} Terdeteksi: ${W}Apache${NC}"

  else
    WEB_ENGINE="unknown"
    echo -e "  ${WARN} Tidak ada web server aktif terdeteksi"
  fi
}

# ============================================================
# MODULE: Apache / httpd
# ============================================================
module_apache() {
  local DIRS=()
  # Deteksi lokasi config Apache
  [ -d /etc/apache2/sites-enabled ]      && DIRS+=("/etc/apache2/sites-enabled")
  [ -d /etc/httpd/conf/sites-enabled ]   && DIRS+=("/etc/httpd/conf/sites-enabled")
  [ -d /etc/httpd/conf.d ]               && DIRS+=("/etc/httpd/conf.d")
  [ -d /usr/local/apache/conf/vhosts ]   && DIRS+=("/usr/local/apache/conf/vhosts")

  for DIR in "${DIRS[@]}"; do
    while IFS= read -r domain; do
      DOMAINS+=("$domain")
    done < <(grep -rh 'ServerName' "$DIR" 2>/dev/null \
      | grep -v '^\s*#' \
      | grep -oE '[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' \
      | grep -Ev 'example|localhost|invalid|\.local$')
  done
}

module_apache_roots() {
  local DIRS=()
  [ -d /etc/apache2/sites-enabled ]    && DIRS+=("/etc/apache2/sites-enabled")
  [ -d /etc/httpd/conf/sites-enabled ] && DIRS+=("/etc/httpd/conf/sites-enabled")
  [ -d /etc/httpd/conf.d ]             && DIRS+=("/etc/httpd/conf.d")
  [ -d /usr/local/apache/conf/vhosts ] && DIRS+=("/usr/local/apache/conf/vhosts")

  for DIR in "${DIRS[@]}"; do
    grep -rh 'ServerName\|DocumentRoot' "$DIR" 2>/dev/null | grep -v '^\s*#' | \
    awk '
      /[Ss]erver[Nn]ame/ { match($0,/[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}/); dom=substr($0,RSTART,RLENGTH) }
      /[Dd]ocument[Rr]oot/ { gsub(/[";]/,"",$2); if(dom) printf "  \033[0;36m→\033[0m %-40s \033[2m%s\033[0m\n",dom,$2; dom="" }
    '
  done
}

# ============================================================
# MODULE: Nginx
# ============================================================
module_nginx() {
  local DIRS=()
  [ -d /etc/nginx/sites-enabled ] && DIRS+=("/etc/nginx/sites-enabled")
  [ -d /etc/nginx/conf.d ]        && DIRS+=("/etc/nginx/conf.d")

  for DIR in "${DIRS[@]}"; do
    while IFS= read -r domain; do
      DOMAINS+=("$domain")
    done < <(grep -rh 'server_name' "$DIR" 2>/dev/null \
      | grep -v '^\s*#' | grep -v 'if\s*(' \
      | grep -oE '[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' \
      | grep -Ev 'example|localhost|invalid|\.local$')
  done
}

module_nginx_roots() {
  local DIRS=()
  [ -d /etc/nginx/sites-enabled ] && DIRS+=("/etc/nginx/sites-enabled")
  [ -d /etc/nginx/conf.d ]        && DIRS+=("/etc/nginx/conf.d")

  for DIR in "${DIRS[@]}"; do
    grep -rh 'server_name\|^\s*root\s\|proxy_pass' "$DIR" 2>/dev/null \
      | grep -v '^\s*#' | grep -v 'if\s*(' | \
    awk '
      /server_name/ { match($0,/[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}/); dom=substr($0,RSTART,RLENGTH) }
      /^\s*root\s/  { gsub(/[;]/,"",$2); if(dom){ printf "  \033[0;36m→\033[0m %-40s \033[2m%s\033[0m\n",dom,$2; dom="" } }
      /proxy_pass/  { gsub(/[;]/,"",$2); if(dom){ printf "  \033[0;36m→\033[0m %-40s \033[2m→ proxy: %s\033[0m\n",dom,$2; dom="" } }
    '
  done
}

# ============================================================
# MODULE: cPanel
# ============================================================
module_cpanel() {
  # cPanel simpan vhost di userdata
  while IFS= read -r domain; do
    DOMAINS+=("$domain")
  done < <(ls /var/cpanel/userdata/ 2>/dev/null | while read -r user; do
    ls /var/cpanel/userdata/"$user"/ 2>/dev/null | grep -v '\.cache\|_SSL\|main'
  done | grep -E '\.' | grep -Ev 'example|localhost')

  # Fallback: httpd conf
  [ -d /etc/apache2/conf.d/userdata ] && \
    while IFS= read -r domain; do
      DOMAINS+=("$domain")
    done < <(grep -rh 'ServerName' /etc/apache2/conf.d/userdata/ 2>/dev/null \
      | grep -v '#' | grep -oE '[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' \
      | grep -Ev 'example|localhost')
}

module_cpanel_roots() {
  ls /var/cpanel/userdata/ 2>/dev/null | while read -r user; do
    for DOMAIN_FILE in /var/cpanel/userdata/"$user"/*/; do
      DOM=$(basename "$DOMAIN_FILE")
      [[ "$DOM" =~ \. ]] || continue
      [[ "$DOM" =~ _SSL$|\.cache$ ]] && continue
      ROOT=$(grep 'documentroot' /var/cpanel/userdata/"$user"/"$DOM" 2>/dev/null | awk '{print $2}')
      [ -n "$ROOT" ] && printf "  ${INFO} %-40s ${DIM}%s${NC}\n" "$DOM" "$ROOT"
    done
  done
}

# ============================================================
# MODULE: ISPConfig
# ============================================================
module_ispconfig() {
  for DIR in /etc/apache2/sites-enabled /etc/nginx/sites-enabled; do
    [ -d "$DIR" ] || continue
    local KEY='ServerName'; [ "$DIR" = "/etc/nginx/sites-enabled" ] && KEY='server_name'
    while IFS= read -r domain; do
      DOMAINS+=("$domain")
    done < <(grep -rh "$KEY" "$DIR" 2>/dev/null \
      | grep -v '#' | grep -v 'if\s*(' \
      | grep -oE '[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' \
      | grep -Ev 'example|localhost')
  done
}

# ============================================================
# MODULE: DirectAdmin
# ============================================================
module_directadmin() {
  while IFS= read -r domain; do
    DOMAINS+=("$domain")
  done < <(ls /home/*/domains/ 2>/dev/null | grep -E '\.' | grep -Ev 'example|localhost')
}

module_directadmin_roots() {
  for USER_DIR in /home/*/domains/*/; do
    DOM=$(echo "$USER_DIR" | awk -F/ '{print $(NF-1)}')
    ROOT="${USER_DIR}public_html"
    [ -d "$ROOT" ] && printf "  ${INFO} %-40s ${DIM}%s${NC}\n" "$DOM" "$ROOT"
  done
}

# ============================================================
# MODULE: Plesk
# ============================================================
module_plesk() {
  while IFS= read -r domain; do
    DOMAINS+=("$domain")
  done < <(ls /var/www/vhosts/ 2>/dev/null \
    | grep -E '\.' | grep -Ev 'example|localhost|default|system')
}

module_plesk_roots() {
  for d in /var/www/vhosts/*/httpdocs; do
    DOM=$(echo "$d" | awk -F/ '{print $5}')
    printf "  ${INFO} %-40s ${DIM}%s${NC}\n" "$DOM" "$d"
  done
}

# ============================================================
# MODULE: OpenLiteSpeed
# ============================================================
module_openlitespeed() {
  while IFS= read -r domain; do
    DOMAINS+=("$domain")
  done < <(grep -rh 'domainName' /usr/local/lsws/conf/vhosts/ 2>/dev/null \
    | grep -oE '[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' \
    | grep -Ev 'example|localhost')
}

module_openlitespeed_roots() {
  grep -rh 'domainName\|docRoot' /usr/local/lsws/conf/vhosts/ 2>/dev/null | \
  awk '
    /domainName/ { match($0,/[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}/); dom=substr($0,RSTART,RLENGTH) }
    /docRoot/    { gsub(/[<>]/,"",$2); if(dom){ printf "  \033[0;36m→\033[0m %-40s \033[2m%s\033[0m\n",dom,$2; dom="" } }
  '
}

# ============================================================
# COLLECT DOMAINS berdasarkan engine
# ============================================================
collect_domains() {
  case "$WEB_ENGINE" in
    nginx)         module_nginx ;;
    apache)        module_apache ;;
    nginx+apache)  module_nginx; module_apache ;;
    cpanel)        module_cpanel ;;
    ispconfig)     module_ispconfig ;;
    directadmin)   module_directadmin ;;
    plesk)         module_plesk ;;
    openlitespeed) module_openlitespeed ;;
    unknown)       module_nginx; module_apache ;; # fallback scan dua engine utama
  esac
  DOMAINS=($(printf '%s\n' "${DOMAINS[@]}" | sort -u))
}

# ============================================================
# SHOW WEB ROOTS berdasarkan engine
# ============================================================
show_webroots() {
  header "WEB ROOT LOCATIONS"
  case "$WEB_ENGINE" in
    nginx)         module_nginx_roots ;;
    apache)        module_apache_roots ;;
    nginx+apache)  module_nginx_roots; module_apache_roots ;;
    cpanel)        module_cpanel_roots ;;
    ispconfig)     module_nginx_roots; module_apache_roots ;;
    directadmin)   module_directadmin_roots ;;
    plesk)         module_plesk_roots ;;
    openlitespeed) module_openlitespeed_roots ;;
    unknown)       module_nginx_roots; module_apache_roots ;;
  esac
}

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
# 2. DETECT ENGINE
# ============================================================
detect_engine

# ============================================================
# 3. DOMAIN DETECTION
# ============================================================
header "DOMAIN DETECTION"
collect_domains

echo -e "  ${INFO} Ditemukan ${W}${#DOMAINS[@]}${NC} domain\n"

if [ ${#DOMAINS[@]} -eq 0 ]; then
  echo -e "  ${WARN} Tidak ada domain terdeteksi"
else
  printf "  %-40s %-14s %-6s %-6s %s\n" "DOMAIN" "DNS" "HTTP" "SSL" "EXPIRE"
  divider

  for DOMAIN in "${DOMAINS[@]}"; do
    # DNS
    RESOLVED=$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | head -1)
    [ -z "$RESOLVED" ] && RESOLVED=$(nslookup "$DOMAIN" 2>/dev/null | grep 'Address:' | tail -1 | awk '{print $2}')
    if [ -z "$RESOLVED" ]; then
      DNS_STATUS="${R}NXDOMAIN${NC}"
    elif [ "$RESOLVED" = "$MYIP" ] || [ "$RESOLVED" = "$LOCALIP" ]; then
      DNS_STATUS="${G}server ini${NC}"
    else
      DNS_STATUS="${Y}${RESOLVED}${NC}"
    fi

    # HTTP
    HTTP_CODE=$(curl -sk --max-time 4 -o /dev/null -w '%{http_code}' "https://${DOMAIN}" 2>/dev/null)
    [ -z "$HTTP_CODE" ] && HTTP_CODE=$(curl -sk --max-time 4 -o /dev/null -w '%{http_code}' "http://${DOMAIN}" 2>/dev/null)
    case "$HTTP_CODE" in
      2*) HTTP_STATUS="${G}${HTTP_CODE}${NC}" ;;
      3*) HTTP_STATUS="${C}${HTTP_CODE}${NC}" ;;
      4*|5*) HTTP_STATUS="${R}${HTTP_CODE}${NC}" ;;
      *) HTTP_STATUS="${DIM}---${NC}" ;;
    esac

    # SSL
    SSL_STATUS="${DIM}N/A${NC}"; SSL_EXPIRE=""
    if command -v openssl &>/dev/null; then
      SSL_INFO=$(echo | timeout 3 openssl s_client -servername "$DOMAIN" \
        -connect "${DOMAIN}:443" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
      if [ -n "$SSL_INFO" ]; then
        EXPIRE_EPOCH=$(date -d "$SSL_INFO" +%s 2>/dev/null)
        DAYS_LEFT=$(( (EXPIRE_EPOCH - $(date +%s)) / 86400 ))
        if   [ "$DAYS_LEFT" -lt 7  ]; then SSL_STATUS="${R}KRITIS${NC}"; SSL_EXPIRE="${R}${DAYS_LEFT}d${NC}"
        elif [ "$DAYS_LEFT" -lt 30 ]; then SSL_STATUS="${Y}OK${NC}";     SSL_EXPIRE="${Y}${DAYS_LEFT}d${NC}"
        else                               SSL_STATUS="${G}OK${NC}";     SSL_EXPIRE="${G}${DAYS_LEFT}d${NC}"
        fi
      fi
    fi

    printf "  %-40s %-14b %-6b %-6b %b\n" "$DOMAIN" "$DNS_STATUS" "$HTTP_STATUS" "$SSL_STATUS" "$SSL_EXPIRE"
  done
fi

# ============================================================
# 4. WEB ROOT LOCATIONS
# ============================================================
show_webroots

# ============================================================
# 5. RUNNING SERVICES
# ============================================================
header "RUNNING SERVICES"
SERVICES=(nginx apache2 httpd lsws mysql mariadb postgresql php-fpm \
  php8.3-fpm php8.2-fpm php8.1-fpm php7.4-fpm fail2ban redis-server memcached)

for SVC in "${SERVICES[@]}"; do
  if systemctl list-units --type=service --all 2>/dev/null | grep -q "${SVC}"; then
    STATUS=$(systemctl is-active "$SVC" 2>/dev/null)
    case "$STATUS" in
      active)   echo -e "  ${PASS} ${SVC}" ;;
      inactive) echo -e "  ${WARN} ${SVC} (inactive)" ;;
      failed)   echo -e "  ${FAIL} ${SVC} (FAILED)" ;;
    esac
  fi
done

# ============================================================
# 6. PHP
# ============================================================
header "PHP"
PHP_BINS=$(update-alternatives --list php 2>/dev/null || \
  find /usr/bin /usr/local/bin -name 'php*' -executable 2>/dev/null | grep -E 'php[0-9.]?$' | sort)
if [ -z "$PHP_BINS" ]; then
  echo -e "  ${FAIL} PHP tidak terinstall"
else
  echo "$PHP_BINS" | while read -r phpbin; do
    VER=$("$phpbin" -v 2>/dev/null | head -1 | awk '{print $2}')
    echo -e "  ${PASS} $phpbin — v${VER}"
  done
fi
SOCKS=$(ls /run/php/*.sock 2>/dev/null)
if [ -n "$SOCKS" ]; then
  echo -e "  ${INFO} FPM sockets:"
  echo "$SOCKS" | while read -r s; do echo -e "    ${DIM}${s}${NC}"; done
fi

# ============================================================
# 7. DATABASE
# ============================================================
header "DATABASE"
if command -v mysql &>/dev/null; then
  if mysql -e "SELECT 1" &>/dev/null 2>&1; then
    DB_SIZE=$(mysql -e "SELECT ROUND(SUM(data_length+index_length)/1024/1024,1) FROM information_schema.tables;" 2>/dev/null | tail -1)
    DB_COUNT=$(mysql -e "SHOW DATABASES;" 2>/dev/null | grep -v Database | wc -l)
    echo -e "  ${PASS} MySQL/MariaDB — ${DB_COUNT} databases, ${DB_SIZE}MB total"
  else
    echo -e "  ${WARN} MySQL/MariaDB — tidak bisa connect (butuh password)"
  fi
else
  echo -e "  ${DIM}MySQL tidak terinstall${NC}"
fi

if command -v psql &>/dev/null; then
  if sudo -u postgres psql -c "SELECT 1" &>/dev/null 2>&1; then
    echo -e "  ${PASS} PostgreSQL — running"
    sudo -u postgres psql -t -c \
      "SELECT datname||' ('||pg_size_pretty(pg_database_size(datname))||')' FROM pg_database ORDER BY pg_database_size(datname) DESC;" \
      2>/dev/null | grep -v '^\s*$' | while read -r line; do
      echo -e "    ${DIM}${line}${NC}"
    done
  else
    echo -e "  ${WARN} PostgreSQL — tidak bisa connect"
  fi
else
  echo -e "  ${DIM}PostgreSQL tidak terinstall${NC}"
fi

# ============================================================
# 8. SECURITY
# ============================================================
header "SECURITY"
if systemctl is-active fail2ban &>/dev/null; then
  BANNED=$(fail2ban-client status sshd 2>/dev/null | grep 'Banned IP' | grep -oE '[0-9]+' | tail -1)
  echo -e "  ${PASS} Fail2ban aktif — ${BANNED:-0} IP banned (SSH)"
else
  echo -e "  ${WARN} Fail2ban tidak aktif"
fi

SSH_PORT=$(grep -E '^Port\s' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
PASS_AUTH=$(grep -E '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
ROOT_LOGIN=$(grep -E '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
echo -e "  ${INFO} SSH port        : ${SSH_PORT:-22}"
[ "$PASS_AUTH" = "yes" ] \
  && echo -e "  ${WARN} PasswordAuth    : yes (pertimbangkan disable)" \
  || echo -e "  ${PASS} PasswordAuth    : ${PASS_AUTH:-default}"
[ "$ROOT_LOGIN" = "yes" ] \
  && echo -e "  ${WARN} PermitRootLogin : yes" \
  || echo -e "  ${PASS} PermitRootLogin : ${ROOT_LOGIN:-default}"

echo -e "\n  ${INFO} Open ports:"
ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' \
  | grep -oE '[0-9]+$' | sort -n | uniq | tr '\n' ' '
echo

# ============================================================
# 9. BASH USERS & LAST LOGIN
# ============================================================
header "BASH USERS & LAST LOGIN"
printf "  ${W}%-18s %-8s %-12s %s${NC}\n" "USER" "UID" "SHELL" "LAST LOGIN"
divider

while IFS=: read -r U_NAME _ U_UID _ _ _ U_SHELL; do
  [[ "$U_SHELL" =~ /(bash|sh|zsh|fish|ksh|tcsh|dash|csh)$ ]] || continue
  [[ "$U_UID" =~ ^[0-9]+$ ]] || continue
  { [ "$U_UID" -eq 0 ] || [ "$U_UID" -ge 1000 ]; } || continue

  U_SHELL_SHORT=$(basename "$U_SHELL")

  U_LAST_LINE=$(lastlog -u "$U_NAME" 2>/dev/null | tail -1)
  if echo "$U_LAST_LINE" | grep -qi "never"; then
    U_LAST_STR="${DIM}Never${NC}"
  else
    U_LAST_RAW=$(last "$U_NAME" 2>/dev/null | grep "^${U_NAME}[[:space:]]" | head -1)
    if [ -n "$U_LAST_RAW" ]; then
      U_LAST_DATE=$(echo "$U_LAST_RAW" | awk '{print $4,$5,$6,$7}')
      U_LAST_STR="${G}${U_LAST_DATE}${NC}"
    else
      U_LAST_STR="${DIM}N/A${NC}"
    fi
  fi

  printf "  %-18s %-8s %-12s %b\n" "$U_NAME" "$U_UID" "$U_SHELL_SHORT" "$U_LAST_STR"
done < /etc/passwd

# ============================================================
# SUMMARY
# ============================================================
header "SUMMARY"
echo -e "  ${INFO} Script    : servercheck.sh v${VERSION} by Rawon Hunter™"
echo -e "  ${INFO} Engine    : ${W}${WEB_ENGINE}${NC}"
echo -e "  ${INFO} Domains   : ${#DOMAINS[@]} terdeteksi"
echo -e "  ${INFO} Disk      : $(df -h / | awk 'NR==2{print $5}') used on /"
echo
