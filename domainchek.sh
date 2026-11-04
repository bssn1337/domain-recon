#!/usr/bin/env bash
# Domain Technology Scanner - portable Bash edition
# Bash 3.2+ | Passive DNS, HTTP(S), TLS and technology fingerprinting.
# No exploitation, brute force, directory enumeration, login attempts or config changes.

set -u
umask 077

VERSION="1.2.0"
REPO_RAW="${REPO_RAW:-https://raw.githubusercontent.com/bssn1337/domain-recon/main}"
DOMAINS_URL="${DOMAINS_URL:-${REPO_RAW}/domains.txt}"
OUTDIR="${OUTDIR:-domain-recon-report}"
TIMEOUT="${TIMEOUT:-12}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-6}"
MAX_DOMAINS="${MAX_DOMAINS:-500}"
USER_AGENT="DomainRecon-Bash/${VERSION}"

log() { printf '%s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

csv_escape() {
    _v=$(printf '%s' "$1" | sed 's/"/""/g')
    printf '"%s"' "$_v"
}

json_escape() {
    # Escape backslash, quote and line breaks using awk; no jq/Python required.
    printf '%s' "$1" | awk 'BEGIN{ORS=""} {
        gsub(/\\/, "\\\\"); gsub(/"/, "\\\"");
        gsub(/\r/, ""); if (NR > 1) printf "\\n"; printf "%s", $0
    }'
}

html_escape() {
    printf '%s' "$1" |
        sed 's/\&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'
}

if ! have curl && ! have wget; then
    log "ERROR: curl atau wget wajib tersedia."
    exit 1
fi

for _cmd in awk sed grep date wc tr cut; do
    if ! have "$_cmd"; then
        log "ERROR: command wajib tidak ditemukan: $_cmd"
        exit 1
    fi
done

TMP="${TMPDIR:-/tmp}/domain-recon.$$"
mkdir -p "$TMP" "$OUTDIR" || exit 1
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT HUP INT TERM

fetch_file() {
    _url="$1"
    _dest="$2"
    _limit="${3:-$TIMEOUT}"

    if have curl; then
        curl -k -fLsS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$_limit" \
            -A "$USER_AGENT" -H 'Cache-Control: no-cache' \
            -o "$_dest" "$_url" 2>/dev/null
    else
        wget -q -T "$_limit" -U "$USER_AGENT" -O "$_dest" "$_url" 2>/dev/null
    fi
}

# Inventory priority:
# 1) File passed as argument
# 2) /root/domain.txt
# 3) /root/domains.txt
# 4) ./domain.txt
# 5) ./domains.txt
# 6) Download domains.txt from GitHub
#
# Never read stdin: when invoked with "curl | bash", stdin contains this script.
INPUT_FILE="${1:-}"
SOURCE_FILE=""

if [ -n "$INPUT_FILE" ]; then
    if [ ! -f "$INPUT_FILE" ] || [ ! -r "$INPUT_FILE" ]; then
        log "ERROR: file inventory tidak dapat dibaca: $INPUT_FILE"
        exit 1
    fi
    SOURCE_FILE="$INPUT_FILE"
elif [ -f "/root/domain.txt" ] && [ -r "/root/domain.txt" ]; then
    SOURCE_FILE="/root/domain.txt"
elif [ -f "/root/domains.txt" ] && [ -r "/root/domains.txt" ]; then
    SOURCE_FILE="/root/domains.txt"
elif [ -f "./domain.txt" ] && [ -r "./domain.txt" ]; then
    SOURCE_FILE="./domain.txt"
elif [ -f "./domains.txt" ] && [ -r "./domains.txt" ]; then
    SOURCE_FILE="./domains.txt"
else
    log "File domain lokal tidak ditemukan. Mengambil inventory dari GitHub:"
    log "$DOMAINS_URL"
    if ! fetch_file "$DOMAINS_URL" "$TMP/domains.txt" 20; then
        log "ERROR: gagal mengambil domains.txt dari GitHub."
        log "Letakkan domain.txt/domains.txt di /root atau direktori kerja."
        exit 1
    fi
    SOURCE_FILE="$TMP/domains.txt"
fi

cp "$SOURCE_FILE" "$TMP/domains-source.txt" || exit 1
if [ ! -s "$TMP/domains-source.txt" ]; then
    log "ERROR: file inventory kosong: $SOURCE_FILE"
    exit 1
fi
log "Inventory digunakan: $SOURCE_FILE"

# Normalize domains; accept bare hostnames or URLs. Strip comments, paths and ports.
awk '
{
    sub(/\r$/, "")
    sub(/[ \t]*#.*/, "")
    gsub(/^[ \t]+|[ \t]+$/, "")
    if ($0 == "") next
    sub(/^https?:\/\//, "")
    sub(/\/.*$/, "")
    sub(/:[0-9]+$/, "")
    $0=tolower($0)
    if ($0 ~ /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/ &&
        $0 !~ /\.\./ && length($0) <= 253) print
}' "$TMP/domains-source.txt" | awk '!seen[$0]++' > "$TMP/targets.txt"

TOTAL=$(wc -l < "$TMP/targets.txt" | tr -d ' ')
if [ "$TOTAL" -eq 0 ]; then
    log "ERROR: tidak ada domain valid di $SOURCE_FILE."
    log "Pastikan formatnya satu domain per baris, contoh: example.com"
    exit 1
fi
if [ "$TOTAL" -gt "$MAX_DOMAINS" ]; then
    log "ERROR: jumlah domain $TOTAL melewati batas MAX_DOMAINS=$MAX_DOMAINS."
    log "Jika memang diperlukan, jalankan: MAX_DOMAINS=1000 bash domainchek.sh"
    exit 1
fi

CSV="$OUTDIR/results.csv"
JSON="$OUTDIR/results.json"
HTML="$OUTDIR/index.html"

printf '%s\n' 'domain,status,final_url,http_server,technologies,tls_expiry,dns_ip,title' > "$CSV"
printf '[\n' > "$JSON"

COUNT=0
REACHABLE=0
FAILED=0

while IFS= read -r DOMAIN || [ -n "$DOMAIN" ]; do
    [ -z "$DOMAIN" ] && continue
    COUNT=$((COUNT + 1))
    log "[$COUNT/$TOTAL] Checking $DOMAIN"

    HEADERS="$TMP/headers"
    BODY="$TMP/body"
    META="$TMP/meta"
    : > "$HEADERS"
    : > "$BODY"
    : > "$META"

    STATUS="000"
    FINAL_URL=""
    SERVER=""
    TITLE=""
    TLS_EXPIRY=""
    DNS_IP=""
    TECH=""

    if have getent; then
        DNS_IP=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1 {print $1}')
    elif have host; then
        DNS_IP=$(host "$DOMAIN" 2>/dev/null | awk '/has address/ {print $4; exit}')
    elif have nslookup; then
        DNS_IP=$(nslookup "$DOMAIN" 2>/dev/null | awk '/^Address: / {ip=$2} END {print ip}')
    fi

    if have curl; then
        STATUS=$(curl -k -L -sS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" \
            -A "$USER_AGENT" -D "$HEADERS" -o "$BODY" -w '%{http_code}' \
            "https://${DOMAIN}/" 2>/dev/null) || STATUS="000"

        FINAL_URL=$(curl -k -L -sS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" \
            -A "$USER_AGENT" -o /dev/null -w '%{url_effective}' \
            "https://${DOMAIN}/" 2>/dev/null)

        if [ "$STATUS" = "000" ] || [ -z "$STATUS" ]; then
            STATUS=$(curl -L -sS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" \
                -A "$USER_AGENT" -D "$HEADERS" -o "$BODY" -w '%{http_code}' \
                "http://${DOMAIN}/" 2>/dev/null) || STATUS="000"

            FINAL_URL=$(curl -L -sS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" \
                -A "$USER_AGENT" -o /dev/null -w '%{url_effective}' \
                "http://${DOMAIN}/" 2>/dev/null)
        fi
    else
        if fetch_file "https://${DOMAIN}/" "$BODY" "$TIMEOUT"; then
            STATUS="200"
            FINAL_URL="https://${DOMAIN}/"
        elif fetch_file "http://${DOMAIN}/" "$BODY" "$TIMEOUT"; then
            STATUS="200"
            FINAL_URL="http://${DOMAIN}/"
        fi
    fi

    if [ "$STATUS" != "000" ] && [ -n "$STATUS" ]; then
        REACHABLE=$((REACHABLE + 1))
    else
        FAILED=$((FAILED + 1))
    fi

    # Case-insensitive header parsing, portable to traditional awk.
    SERVER=$(awk 'tolower($1)=="server:" {
        $1=""; sub(/^[ \t]+/, ""); gsub(/\r/, ""); print; exit
    }' "$HEADERS")

    TITLE=$(tr '\n' ' ' < "$BODY" |
        sed -n 's/.*<[Tt][Ii][Tt][Ll][Ee][^>]*>\([^<]*\)<\/[Tt][Ii][Tt][Ll][Ee]>.*/\1/p' |
        cut -c1-180)
    TITLE=$(printf '%s' "$TITLE" | sed 's/^[ \t]*//; s/[ \t]*$//')

    if have openssl; then
        if have timeout; then
            TLS_EXPIRY=$(
                (echo | timeout 7 openssl s_client -servername "$DOMAIN" \
                    -connect "${DOMAIN}:443" 2>/dev/null) |
                openssl x509 -noout -enddate 2>/dev/null |
                sed 's/^notAfter=//'
            )
        else
            TLS_EXPIRY=$(
                (echo | openssl s_client -servername "$DOMAIN" \
                    -connect "${DOMAIN}:443" 2>/dev/null) |
                openssl x509 -noout -enddate 2>/dev/null |
                sed 's/^notAfter=//'
            )
        fi
    fi

    cat "$HEADERS" "$BODY" > "$META"

    addtech() {
        if [ -z "$TECH" ]; then TECH="$1"; else TECH="${TECH}; $1"; fi
    }
    sig() { grep -Eqi "$1" "$META"; }

    # CMS
    if sig 'wp-content|wp-includes|wordpress'; then addtech "WordPress"; fi
    if sig 'Joomla|com_content|/media/system/js/'; then addtech "Joomla"; fi
    if sig 'Drupal.settings|/sites/default/files/|content="Drupal'; then addtech "Drupal"; fi
    if sig 'Magento|mage-cache|/static/version[0-9]+/'; then addtech "Magento"; fi
    if sig 'Shopify|cdn.shopify.com'; then addtech "Shopify"; fi
    if sig 'PrestaShop|prestashop'; then addtech "PrestaShop"; fi
    if sig 'OpenCart|catalog/view/theme'; then addtech "OpenCart"; fi
    if sig 'Ghost|ghost-url'; then addtech "Ghost"; fi
    if sig 'Moodle|/theme/yui_combo.php'; then addtech "Moodle"; fi

    # Backend/framework hints
    if sig 'laravel_session|XSRF-TOKEN'; then addtech "Laravel (indikasi)"; fi
    if sig 'ci_session|CodeIgniter'; then addtech "CodeIgniter (indikasi)"; fi
    if sig 'Symfony|sf-toolbar'; then addtech "Symfony"; fi
    if sig 'next/static|__NEXT_DATA__'; then addtech "Next.js"; fi
    if sig 'nuxt|_nuxt/'; then addtech "Nuxt"; fi
    if sig 'Django'; then addtech "Django (indikasi)"; fi
    if sig 'express'; then addtech "Express.js (indikasi)"; fi

    # Frontend
    if sig 'react-dom|react.production|__REACT'; then addtech "React"; fi
    if sig 'vue(\.runtime)?(\.min)?\.js|__VUE__'; then addtech "Vue.js"; fi
    if sig 'ng-version|angular(\.min)?\.js'; then addtech "Angular"; fi
    if sig 'jquery(\.min)?\.js|jQuery v'; then addtech "jQuery"; fi
    if sig 'bootstrap(\.min)?\.(css|js)'; then addtech "Bootstrap"; fi
    if sig 'tailwindcss|tailwind\.min\.css'; then addtech "Tailwind CSS"; fi

    # Web server and runtime hints
    case "$SERVER" in
        *nginx*|*Nginx*) addtech "Nginx" ;;
        *Apache*|*apache*) addtech "Apache" ;;
        *LiteSpeed*|*litespeed*) addtech "LiteSpeed" ;;
        *Microsoft-IIS*|*IIS*) addtech "IIS" ;;
    esac
    if sig 'PHPSESSID|X-Powered-By: PHP'; then addtech "PHP (indikasi)"; fi
    if sig 'X-Powered-By: Express|connect.sid'; then addtech "Node.js/Express (indikasi)"; fi
    if [ -z "$TECH" ]; then TECH="Tidak terdeteksi"; fi

    # CSV
    printf '%s,' "$(csv_escape "$DOMAIN")" >> "$CSV"
    printf '%s,' "$(csv_escape "$STATUS")" >> "$CSV"
    printf '%s,' "$(csv_escape "$FINAL_URL")" >> "$CSV"
    printf '%s,' "$(csv_escape "$SERVER")" >> "$CSV"
    printf '%s,' "$(csv_escape "$TECH")" >> "$CSV"
    printf '%s,' "$(csv_escape "$TLS_EXPIRY")" >> "$CSV"
    printf '%s,' "$(csv_escape "$DNS_IP")" >> "$CSV"
    printf '%s\n' "$(csv_escape "$TITLE")" >> "$CSV"

    # JSON
    [ "$COUNT" -gt 1 ] && printf ',\n' >> "$JSON"
    printf '  {"domain":"%s","status":"%s","final_url":"%s","server":"%s","technologies":"%s","tls_expiry":"%s","dns_ip":"%s","title":"%s"}' \
        "$(json_escape "$DOMAIN")" \
        "$(json_escape "$STATUS")" \
        "$(json_escape "$FINAL_URL")" \
        "$(json_escape "$SERVER")" \
        "$(json_escape "$TECH")" \
        "$(json_escape "$TLS_EXPIRY")" \
        "$(json_escape "$DNS_IP")" \
        "$(json_escape "$TITLE")" >> "$JSON"

done < "$TMP/targets.txt"

printf '\n]\n' >> "$JSON"

# HTML dashboard: build rows directly from the collected result data.
cat > "$HTML" <<'HTML_HEAD'
<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Domain Technology Scanner</title>
<style>
body{font:14px system-ui,Arial;margin:0;background:#0b1220;color:#e5e7eb}
header{padding:24px 4%;background:#111c30}
h1{margin:0 0 6px;font-size:24px}.muted{color:#9ca3af}
.wrap{padding:22px 4%}.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.card{background:#172338;padding:16px 20px;border-radius:10px;min-width:130px}
.num{font-size:25px;font-weight:700}
input{padding:10px;border:1px solid #334155;border-radius:7px;background:#111c30;color:white;width:min(420px,90%)}
table{width:100%;border-collapse:collapse;margin-top:14px;background:#111c30}
th,td{text-align:left;padding:11px;border-bottom:1px solid #263449;vertical-align:top}
th{color:#93c5fd}tr:hover{background:#172338}
.foot{margin-top:20px;color:#9ca3af;font-size:12px}
</style></head><body>
<header><h1>Domain Technology Scanner</h1>
<div class="muted">Passive HTTP/DNS/TLS fingerprinting · Bash edition</div></header>
<main class="wrap">
<div class="cards">
<div class="card"><div class="muted">Total domain</div><div class="num" id="total">0</div></div>
<div class="card"><div class="muted">HTTP reachable</div><div class="num" id="reachable">0</div></div>
<div class="card"><div class="muted">Unreachable</div><div class="num" id="failed">0</div></div>
</div>
<input id="q" placeholder="Cari domain, teknologi, server..." oninput="filterRows()">
<div style="overflow:auto"><table>
<thead><tr><th>Domain</th><th>Status</th><th>Final URL</th><th>Web server</th><th>Teknologi</th><th>DNS IP</th><th>TLS expiry</th><th>Title</th></tr></thead>
<tbody id="rows">
HTML_HEAD

# Read CSV fields (generated by this script); values are quoted.
while IFS=, read -r D S U SRV T TLS IP TITLE; do
    [ "$D" = '"domain"' ] && continue
    for V in "$D" "$S" "$U" "$SRV" "$T" "$IP" "$TLS" "$TITLE"; do
        V=$(printf '%s' "$V" | sed 's/^"//; s/"$//; s/""/"/g')
        ESCAPED=$(html_escape "$V")
        case "$V" in
            "$D") ROW="${ROW-}<td>${ESCAPED}</td>" ;;
        esac
    done
    # Build row explicitly to preserve column order.
    D=$(printf '%s' "$D" | sed 's/^"//;s/"$//;s/""/"/g')
    S=$(printf '%s' "$S" | sed 's/^"//;s/"$//;s/""/"/g')
    U=$(printf '%s' "$U" | sed 's/^"//;s/"$//;s/""/"/g')
    SRV=$(printf '%s' "$SRV" | sed 's/^"//;s/"$//;s/""/"/g')
    T=$(printf '%s' "$T" | sed 's/^"//;s/"$//;s/""/"/g')
    TLS=$(printf '%s' "$TLS" | sed 's/^"//;s/"$//;s/""/"/g')
    IP=$(printf '%s' "$IP" | sed 's/^"//;s/"$//;s/""/"/g')
    TITLE=$(printf '%s' "$TITLE" | sed 's/^"//;s/"$//;s/""/"/g')
    printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
        "$(html_escape "$D")" "$(html_escape "$S")" "$(html_escape "$U")" \
        "$(html_escape "$SRV")" "$(html_escape "$T")" "$(html_escape "$IP")" \
        "$(html_escape "$TLS")" "$(html_escape "$TITLE")" >> "$HTML"
done < "$CSV"

cat >> "$HTML" <<'HTML_TAIL'
</tbody></table></div>
<div class="foot">Hasil bersifat indikatif berdasarkan respons publik. Teknologi yang tidak mengekspos signature mungkin tidak terdeteksi. Tidak ada exploit atau percobaan login.</div>
</main>
<script>
const rows=[...document.querySelectorAll('#rows tr')];
document.getElementById('total').textContent=rows.length;
document.getElementById('reachable').textContent=rows.filter(r=>r.cells[1].textContent!=='000').length;
document.getElementById('failed').textContent=rows.length-Number(document.getElementById('reachable').textContent);
function filterRows(){let q=document.getElementById('q').value.toLowerCase();rows.forEach(r=>r.style.display=r.textContent.toLowerCase().includes(q)?'':'none')}
</script></body></html>
HTML_TAIL

log ""
log "Scan selesai."
log "Inventory       : $SOURCE_FILE"
log "Total domain    : $TOTAL"
log "HTTP reachable  : $REACHABLE"
log "Tidak terjangkau: $FAILED"
log "Dashboard       : $HTML"
log "JSON            : $JSON"
log "CSV             : $CSV"
log "Catatan: fingerprint bersifat indikatif, berdasarkan informasi yang terlihat dari sisi publik."
