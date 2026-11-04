#!/usr/bin/env bash
# Domain Technology Scanner - standalone portable Bash edition
# Bash 3.2+; passive DNS/HTTP/TLS fingerprinting only.
# No exploit, brute force, directory enumeration, login attempts, or config changes.

set -u
umask 077

VERSION="1.1.0"
REPO_RAW="${REPO_RAW:-https://raw.githubusercontent.com/bssn1337/domain-recon/main}"
DOMAINS_URL="${DOMAINS_URL:-${REPO_RAW}/domains.txt}"
INPUT_FILE="${1:-}"
OUTDIR="${OUTDIR:-domain-recon-report}"
TIMEOUT="${TIMEOUT:-12}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-6}"
MAX_DOMAINS="${MAX_DOMAINS:-500}"
USER_AGENT="DomainRecon-Bash/${VERSION}"

have() { command -v "$1" >/dev/null 2>&1; }
log() { printf '%s\n' "$*" >&2; }
csv_escape() { v=$(printf '%s' "$1" | sed 's/"/""/g'); printf '"%s"' "$v"; }
json_escape() {
  printf '%s' "$1" | awk 'BEGIN{ORS=""} {gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\r/, ""); if (NR>1) printf "\\n"; printf "%s", $0}'
}
html_escape() {
  printf '%s' "$1" | sed 's/\&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g;s/"/\&quot;/g'
}

if ! have bash; then echo "ERROR: Bash required." >&2; exit 1; fi
if ! have curl && ! have wget; then echo "ERROR: curl or wget required." >&2; exit 1; fi
for cmd in awk sed grep date wc tr; do
  if ! have "$cmd"; then echo "ERROR: required command missing: $cmd" >&2; exit 1; fi
done

TMP="${TMPDIR:-/tmp}/domain-recon.$$"
mkdir -p "$TMP" "$OUTDIR" || exit 1
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT HUP INT TERM

fetch() {
  url="$1"; dest="$2"; max_time="${3:-$TIMEOUT}"
  if have curl; then
    curl -k -L -sS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$max_time" \
      -A "$USER_AGENT" -H 'Cache-Control: no-cache' -o "$dest" "$url" 2>/dev/null
  else
    wget -q -T "$max_time" -U "$USER_AGENT" -O "$dest" "$url" 2>/dev/null
  fi
}

# IMPORTANT: Never read stdin. With curl | bash, stdin contains this script.
# The inventory is downloaded from the repository, or supplied as a filename argument.
if [ -n "$INPUT_FILE" ]; then
  if [ ! -r "$INPUT_FILE" ]; then log "ERROR: cannot read input file: $INPUT_FILE"; exit 1; fi
  cp "$INPUT_FILE" "$TMP/domains.txt" || exit 1
else
  log "Downloading inventory: $DOMAINS_URL"
  if ! fetch "$DOMAINS_URL" "$TMP/domains.txt" 20; then
    log "ERROR: cannot download domains.txt from GitHub."
    log "Upload domains.txt to the repository root, beside domainchek.sh."
    exit 1
  fi
fi

if [ ! -s "$TMP/domains.txt" ]; then
  log "ERROR: domains.txt is empty or unavailable."
  exit 1
fi

awk '
{
  sub(/\r$/, "")
  gsub(/^[ \t]+|[ \t]+$/, "")
  if ($0 == "" || $0 ~ /^#/) next
  sub(/^https?:\/\//, "")
  sub(/\/.*$/, "")
  sub(/:[0-9]+$/, "")
  $0=tolower($0)
  if ($0 ~ /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/ && $0 !~ /\.\./ && length($0)<=253) print
}' "$TMP/domains.txt" | awk '!seen[$0]++' > "$TMP/targets.txt"

TOTAL=$(wc -l < "$TMP/targets.txt" | tr -d ' ')
if [ "$TOTAL" -eq 0 ]; then log "ERROR: no valid domains found."; exit 1; fi
if [ "$TOTAL" -gt "$MAX_DOMAINS" ]; then
  log "ERROR: $TOTAL domains exceed limit $MAX_DOMAINS. Set MAX_DOMAINS to raise it."
  exit 1
fi

CSV="$OUTDIR/results.csv"
JSON="$OUTDIR/results.json"
HTML="$OUTDIR/index.html"
printf '%s\n' 'domain,status,final_url,http_server,technologies,tls_expiry,dns_ip,title' > "$CSV"
printf '[\n' > "$JSON"

count=0; reachable=0; failed=0

while IFS= read -r domain || [ -n "$domain" ]; do
  [ -z "$domain" ] && continue
  count=$((count + 1))
  log "[$count/$TOTAL] Checking $domain"

  headers="$TMP/headers"; body="$TMP/body"; meta="$TMP/meta"
  : > "$headers"; : > "$body"; : > "$meta"

  status="000"; final_url=""; server=""; title=""; tls_expiry=""; dns_ip=""; tech=""

  if have getent; then
    dns_ip=$(getent ahostsv4 "$domain" 2>/dev/null | awk 'NR==1{print $1}')
  elif have host; then
    dns_ip=$(host "$domain" 2>/dev/null | awk '/has address/{print $4; exit}')
  elif have nslookup; then
    dns_ip=$(nslookup "$domain" 2>/dev/null | awk '/^Address: /{ip=$2} END{print ip}')
  fi

  if have curl; then
    status=$(curl -k -L -sS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" \
      -A "$USER_AGENT" -D "$headers" -o "$body" -w '%{http_code}' "https://${domain}/" 2>/dev/null) || status="000"
    final_url=$(curl -k -L -sS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" \
      -A "$USER_AGENT" -o /dev/null -w '%{url_effective}' "https://${domain}/" 2>/dev/null)
    if [ "$status" = "000" ] || [ -z "$status" ]; then
      status=$(curl -L -sS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" \
        -A "$USER_AGENT" -D "$headers" -o "$body" -w '%{http_code}' "http://${domain}/" 2>/dev/null) || status="000"
      final_url=$(curl -L -sS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" \
        -A "$USER_AGENT" -o /dev/null -w '%{url_effective}' "http://${domain}/" 2>/dev/null)
    fi
  else
    if fetch "https://${domain}/" "$body" "$TIMEOUT"; then status="200"; final_url="https://${domain}/"
    elif fetch "http://${domain}/" "$body" "$TIMEOUT"; then status="200"; final_url="http://${domain}/"
    fi
  fi

  if [ "$status" != "000" ] && [ -n "$status" ]; then reachable=$((reachable + 1))
  else failed=$((failed + 1)); fi

  server=$(awk 'tolower($1)=="server:" {$1=""; sub(/^[ \t]+/,""); gsub(/\r/,""); print; exit}' "$headers")
  title=$(tr '\n' ' ' < "$body" | sed -n 's/.*<[Tt][Ii][Tt][Ll][Ee][^>]*>\([^<]*\)<\/[Tt][Ii][Tt][Ll][Ee]>.*/\1/p' | cut -c1-180)
  title=$(printf '%s' "$title" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

  if have openssl && have timeout; then
    tls_expiry=$( (echo | timeout 7 openssl s_client -servername "$domain" -connect "${domain}:443" 2>/dev/null) |
      openssl x509 -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
  elif have openssl; then
    tls_expiry=$( (echo | openssl s_client -servername "$domain" -connect "${domain}:443" 2>/dev/null) |
      openssl x509 -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
  fi

  cat "$headers" "$body" > "$meta"
  addtech() { if [ -z "$tech" ]; then tech="$1"; else tech="${tech}; $1"; fi; }
  sig() { grep -Eqi "$1" "$meta"; }

  if sig 'wp-content|wp-includes|wordpress'; then addtech "WordPress"; fi
  if sig 'Joomla|com_content|/media/system/js/'; then addtech "Joomla"; fi
  if sig 'Drupal.settings|/sites/default/files/|content="Drupal'; then addtech "Drupal"; fi
  if sig 'Magento|mage-cache|/static/version[0-9]+/'; then addtech "Magento"; fi
  if sig 'Shopify|cdn.shopify.com'; then addtech "Shopify"; fi
  if sig 'PrestaShop|prestashop'; then addtech "PrestaShop"; fi
  if sig 'OpenCart|catalog/view/theme'; then addtech "OpenCart"; fi
  if sig 'Ghost|ghost-url'; then addtech "Ghost"; fi
  if sig 'Moodle|/theme/yui_combo.php'; then addtech "Moodle"; fi
  if sig 'laravel_session|XSRF-TOKEN'; then addtech "Laravel (indikasi)"; fi
  if sig 'ci_session|CodeIgniter'; then addtech "CodeIgniter (indikasi)"; fi
  if sig 'Symfony|sf-toolbar'; then addtech "Symfony"; fi
  if sig 'next/static|__NEXT_DATA__'; then addtech "Next.js"; fi
  if sig 'nuxt|_nuxt/'; then addtech "Nuxt"; fi
  if sig 'react-dom|react.production|__REACT'; then addtech "React"; fi
  if sig 'vue(\.runtime)?(\.min)?\.js|__VUE__'; then addtech "Vue.js"; fi
  if sig 'ng-version|angular(\.min)?\.js'; then addtech "Angular"; fi
  if sig 'jquery(\.min)?\.js|jQuery v'; then addtech "jQuery"; fi
  if sig 'bootstrap(\.min)?\.(css|js)'; then addtech "Bootstrap"; fi
  if sig 'tailwindcss|tailwind\.min\.css'; then addtech "Tailwind CSS"; fi
  if sig 'Django'; then addtech "Django (indikasi)"; fi
  if sig 'express'; then addtech "Express.js (indikasi)"; fi
  case "$server" in
    *nginx*|*Nginx*) addtech "Nginx";;
    *Apache*|*apache*) addtech "Apache";;
    *LiteSpeed*|*litespeed*) addtech "LiteSpeed";;
    *Microsoft-IIS*|*IIS*) addtech "IIS";;
  esac
  if sig 'PHPSESSID|X-Powered-By: PHP'; then addtech "PHP (indikasi)"; fi
  if sig 'X-Powered-By: Express|connect.sid'; then addtech "Node.js/Express (indikasi)"; fi
  [ -z "$tech" ] && tech="Tidak terdeteksi"

  printf '%s,' "$(csv_escape "$domain")" >> "$CSV"
  printf '%s,' "$(csv_escape "$status")" >> "$CSV"
  printf '%s,' "$(csv_escape "$final_url")" >> "$CSV"
  printf '%s,' "$(csv_escape "$server")" >> "$CSV"
  printf '%s,' "$(csv_escape "$tech")" >> "$CSV"
  printf '%s,' "$(csv_escape "$tls_expiry")" >> "$CSV"
  printf '%s,' "$(csv_escape "$dns_ip")" >> "$CSV"
  printf '%s\n' "$(csv_escape "$title")" >> "$CSV"

  [ "$count" -gt 1 ] && printf ',\n' >> "$JSON"
  printf '  {"domain":"%s","status":"%s","final_url":"%s","server":"%s","technologies":"%s","tls_expiry":"%s","dns_ip":"%s","title":"%s"}' \
    "$(json_escape "$domain")" "$(json_escape "$status")" "$(json_escape "$final_url")" \
    "$(json_escape "$server")" "$(json_escape "$tech")" "$(json_escape "$tls_expiry")" \
    "$(json_escape "$dns_ip")" "$(json_escape "$title")" >> "$JSON"
done < "$TMP/targets.txt"
printf '\n]\n' >> "$JSON"

cat > "$HTML" <<'HTML_HEAD'
<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Domain Technology Scanner</title><style>
body{font:14px system-ui,Arial;margin:0;background:#0b1220;color:#e5e7eb}header{padding:24px 4%;background:#111c30}
h1{margin:0 0 6px;font-size:24px}.muted{color:#9ca3af}.wrap{padding:22px 4%}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}.card{background:#172338;padding:16px 20px;border-radius:10px;min-width:130px}
.num{font-size:25px;font-weight:700}input{padding:10px;border:1px solid #334155;border-radius:7px;background:#111c30;color:white;width:min(420px,90%)}
table{width:100%;border-collapse:collapse;margin-top:14px;background:#111c30}th,td{text-align:left;padding:11px;border-bottom:1px solid #263449;vertical-align:top}th{color:#93c5fd}
tr:hover{background:#172338}.foot{margin-top:20px;color:#9ca3af;font-size:12px}
</style></head><body><header><h1>Domain Technology Scanner</h1><div class="muted">Passive HTTP/DNS/TLS fingerprinting · Bash edition</div></header><main class="wrap">
<div class="cards"><div class="card"><div class="muted">Total domain</div><div class="num" id="total">0</div></div>
<div class="card"><div class="muted">HTTP reachable</div><div class="num" id="reachable">0</div></div>
<div class="card"><div class="muted">Unreachable</div><div class="num" id="failed">0</div></div></div>
<input id="q" placeholder="Cari domain, teknologi, server..." oninput="filterRows()">
<div style="overflow:auto"><table><thead><tr><th>Domain</th><th>Status</th><th>Web server</th><th>Teknologi</th><th>DNS IP</th><th>TLS expiry</th><th>Title</th></tr></thead><tbody id="rows">
HTML_HEAD

while IFS=, read -r d s u srv tech tls ip title; do
  [ "$d" = '"domain"' ] && continue
  vals=""
  for v in "$d" "$s" "$srv" "$tech" "$ip" "$tls" "$title"; do
    v=$(printf '%s' "$v" | sed 's/^"//;s/"$//;s/""/"/g')
    vals="${vals}<td>$(html_escape "$v")</td>"
  done
  printf '<tr>%s</tr>\n' "$vals" >> "$HTML"
done < "$CSV"

cat >> "$HTML" <<'HTML_TAIL'
</tbody></table></div><div class="foot">Hasil indikatif dari respons publik. Teknologi yang tidak mengekspos signature mungkin tidak terdeteksi. Tidak ada exploit atau percobaan login.</div>
</main><script>
const rows=[...document.querySelectorAll('#rows tr')];
document.getElementById('total').textContent=rows.length;
document.getElementById('reachable').textContent=rows.filter(r=>r.cells[1].textContent!=='000').length;
document.getElementById('failed').textContent=rows.length-Number(document.getElementById('reachable').textContent);
function filterRows(){let q=document.getElementById('q').value.toLowerCase();rows.forEach(r=>r.style.display=r.textContent.toLowerCase().includes(q)?'':'none')}
</script></body></html>
HTML_TAIL

log ""
log "Scan selesai."
log "Total domain    : $TOTAL"
log "HTTP reachable  : $reachable"
log "Tidak terjangkau: $failed"
log "Dashboard       : $HTML"
log "JSON            : $JSON"
log "CSV             : $CSV"
