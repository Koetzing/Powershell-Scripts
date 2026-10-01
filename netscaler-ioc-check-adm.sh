#!/bin/sh
# ------------------------------------------------------------------------------
# netscaler-ioc-check-adm.sh   -   ADM-Variante des IOC-/CVE-Triage-Skripts
# Bulletin CTX697096 (CVE-2026-88771 ... 88778). Read-only, keine Aenderungen.
#
# Aufruf:  sh netscaler-ioc-check-adm.sh <SELEKTOR>
#   Ein SELEKTOR -> prueft genau EINEN Indikator und endet mit Exit-Code:
#       0 = OK / sauber   -> ADM-Status "Completed"
#       1 = Fund/pruefen  -> ADM-Status "Failed"
#       (unklar/nicht verifizierbar wird konservativ als Fund = Exit 1 gewertet)
#
#   REPORT  -> fuehrt alle Indikatoren aus, schreibt Vollreport nach /var/tmp,
#              Exit immer 0 (fuer die Detailansicht pro Box)
#   ALL     -> alle Indikatoren, Exit 1 sobald irgendein Fund (einzelner Sammelstatus)
#
# SELEKTOREN:
#   fw         Firmware unterhalb Fixed Build (14.1-73.37 / 13.1-64.23 / FIPS 37.279)
#   isn        CVE-2026-88778: Enhanced ISN nicht ENABLED trotz passender vServer
#   httpdioc   httpd.conf enthaelt b64decode/base64/LogonPoint/custom//bin/sh
#   shellsuid  /bin/sh setuid/setgid gesetzt oder /bin/sh fehlt
#   dotfiles   .dot-Dateien unter LogonPoint/custom
#   hiddenvpn  versteckte Dateien unter /netscaler/ns_gui/vpn
#   b64logs    b64decode/base64_decode in HTTP-/System-Logs
#   crash      neue core/crash-Dateien (<14 Tage)
#   callhome   callhome_tmps*-Dateien unter /var/tmp
#   rcpython   python-Referenzen in rc.netscaler
#   nobodyproc Prozesse als 'nobody' ausser httpd
#   nobodycron crontab-Eintraege fuer 'nobody'
#
# --- ADM-Config-Job -----------------------------------------------------------
# 1x put (Skript nach /var/tmp/netscaler-ioc-check-adm.sh), dann je ein Kommando:
#     shell sh /var/tmp/netscaler-ioc-check-adm.sh fw
#     shell sh /var/tmp/netscaler-ioc-check-adm.sh isn
#     shell sh /var/tmp/netscaler-ioc-check-adm.sh httpdioc
#     ... (weitere Selektoren nach Bedarf) ...
#     shell sh /var/tmp/netscaler-ioc-check-adm.sh REPORT
# "On Command Failure" = "Ignore error and continue" setzen.
# In der Execution Summary zeigt die Status-Spalte je Kommando: Completed = sauber,
# Failed = Fund -> auf dieser Box pruefen (Detail im /var/tmp-Report).
# ------------------------------------------------------------------------------

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
umask 077

CONFIG="${NSCONF:-/nsconfig/ns.conf}"
HOST=$(hostname 2>/dev/null || echo unknown-host)
SEL="${1:-ALL}"

# ---- Firmware-Build erkennen -------------------------------------------------
detect_build() {
    vline=''
    [ -r "$CONFIG" ] && vline=$(head -n 5 "$CONFIG" 2>/dev/null | grep -iE '^#NS[0-9]+\.[0-9]+ Build' | head -1)
    if [ -z "$vline" ] && command -v nsconmsg >/dev/null 2>&1; then
        vline=$(nsconmsg -K /var/nslog/newnslog -d setime 2>/dev/null | grep -iE 'NS[0-9]+\.[0-9]+ Build' | head -1)
    fi
    printf '%s\n' "$vline" | sed -E -n 's/.*NS([0-9]+\.[0-9]+) Build ([0-9]+\.[0-9]+).*/\1 \2/p'
}

# cur >= req ?  (major.minor)   0=ja, 1=nein
ver_ge() {
    cm=${1%%.*}; cn=${1##*.}; rm=${2%%.*}; rn=${2##*.}
    [ "$cm" -gt "$rm" ] && return 0
    [ "$cm" -lt "$rm" ] && return 1
    [ "$cn" -ge "$rn" ] && return 0
    return 1
}

# erforderlichen Fixed Build zur Familie ermitteln -> setzt REQ
required_build() {
    case "$1" in
        14.1) REQ=73.37 ;;
        13.1) if printf '%s' "$2" | grep -q '^37\.' || grep -Eiq 'FIPS|NDcPP' "$CONFIG" 2>/dev/null; then REQ=37.279; else REQ=64.23; fi ;;
        *)    REQ='' ;;
    esac
}

# Gate: laeuft die Box bereits auf dem Ziel-Build (>= 14.1-73.37 bzw. 13.1-64.23/37.279)?
# 0 = ja (bereit), 1 = nein/unbekannt ; setzt READY mit Klartext.
is_ready() {
    set -- $(detect_build); fam=$1; bld=$2
    if [ -z "$fam" ] || [ -z "$bld" ]; then READY="UNKNOWN(build?)"; return 1; fi
    required_build "$fam" "$bld"
    if [ -z "$REQ" ]; then READY="UNKNOWN(fam $fam)"; return 1; fi
    if ver_ge "$bld" "$REQ"; then READY="$fam-$bld"; return 0
    else READY="UPGRADE_PENDING($fam-$bld<$REQ)"; return 1; fi
}

# ---- Einzelpruefungen: setzen R (OK|FUND|CHECK) und geben 0/1 zurueck --------
chk_fw() {
    set -- $(detect_build)
    fam=$1; bld=$2
    if [ -z "$fam" ] || [ -z "$bld" ]; then R="CHECK(build?)"; return 1; fi
    case "$fam" in
        14.1) req=73.37 ;;
        13.1) if printf '%s' "$bld" | grep -q '^37\.' || grep -Eiq 'FIPS|NDcPP' "$CONFIG" 2>/dev/null; then req=37.279; else req=64.23; fi ;;
        *)    R="CHECK(fam $fam)"; return 1 ;;
    esac
    if ver_ge "$bld" "$req"; then R="OK($fam-$bld>=$req)"; return 0
    else R="FUND($fam-$bld<$req)"; return 1; fi
}

chk_isn() {
    [ -r "$CONFIG" ] || { R="CHECK(no config)"; return 1; }
    isn=DISABLED_DEFAULT
    grep -Eiq '^[[:space:]]*set ns tcpParam .*-enhancedISNGeneration[[:space:]]+ENABLED'  "$CONFIG" && isn=ENABLED
    grep -Eiq '^[[:space:]]*set ns tcpParam .*-enhancedISNGeneration[[:space:]]+DISABLED' "$CONFIG" && isn=DISABLED
    vs=$(grep -Ei '^[[:space:]]*add (lb|cs|vpn|authentication|gslb|cr) vserver .* (HTTP|SSL|SSL_BRIDGE|TCP|SSL_TCP|FTP|NNTP|RTSP|RDP|DNS_TCP|DOT|SIP_TCP|SIP_SSL|DIAMETER|SSL_DIAMETER|MYSQL|MSSQL|ORACLE|SMPP|MQTT|MQTT_TLS|MONGO|MONGO_TLS|PROXY|SSL_PROXY|USER_TCP|USER_SSL_TCP)([[:space:]]|$)' "$CONFIG" 2>/dev/null | head -1)
    if [ -n "$vs" ] && [ "$isn" != "ENABLED" ]; then R="FUND(ISN=$isn, vServer vorhanden)"; return 1
    else R="OK(ISN=$isn)"; return 0; fi
}

chk_httpdioc() {
    found=''
    for f in /etc/httpd.conf /nsconfig/httpd.conf /netscaler/httpd.conf; do
        [ -r "$f" ] || continue
        if grep -Eiq 'b64decode|base64|LogonPoint/custom|/bin/sh' "$f" 2>/dev/null; then found="$found $f"; fi
    done
    if [ -n "$found" ]; then R="FUND(httpd.conf:$found)"; return 1; else R="OK"; return 0; fi
}

chk_shellsuid() {
    if [ ! -e /bin/sh ]; then R="FUND(/bin/sh fehlt)"; return 1; fi
    mode=$(ls -l /bin/sh 2>/dev/null | awk 'NR==1{print $1}')
    case "$mode" in
        *s*) R="FUND(setuid $mode)"; return 1 ;;
        '')  R="CHECK(mode?)"; return 1 ;;
        *)   R="OK($mode)"; return 0 ;;
    esac
}

chk_dotfiles() {
    d=/var/netscaler/logon/LogonPoint/custom
    [ -d "$d" ] || { R="OK(kein $d)"; return 0; }
    hit=$(find "$d" -name '*.dot' -print 2>/dev/null | head -20)
    if [ -n "$hit" ]; then R="FUND(.dot)"; return 1; else R="OK"; return 0; fi
}

chk_hiddenvpn() {
    d=/netscaler/ns_gui/vpn
    [ -d "$d" ] || { R="OK(kein $d)"; return 0; }
    hit=$(find "$d" -type f -name '.*' -print 2>/dev/null | head -20)
    if [ -n "$hit" ]; then R="FUND(hidden)"; return 1; else R="OK"; return 0; fi
}

chk_b64logs() {
    hit=''
    for d in /var/log /var/nslog; do
        [ -d "$d" ] || continue
        for f in "$d"/*http*access* "$d"/*http* "$d"/ns.log "$d"/messages; do
            [ -f "$f" ] && [ -r "$f" ] || continue
            case "$f" in
                *.gz)  m=$(zgrep -Ei 'b64decode|base64_decode' "$f" 2>/dev/null | head -1) ;;
                *.bz2|*.xz) continue ;;
                *)     m=$(grep -Ei 'b64decode|base64_decode' "$f" 2>/dev/null | head -1) ;;
            esac
            [ -n "$m" ] && hit="$hit $f"
        done
    done
    if [ -n "$hit" ]; then R="FUND(logs:$hit)"; return 1; else R="OK"; return 0; fi
}

chk_crash() {
    hit=$(find /var/core /var/crash -type f ! -name bounds -mtime -14 -print 2>/dev/null | head -20)
    if [ -n "$hit" ]; then R="FUND(core<14d)"; return 1; else R="OK"; return 0; fi
}

chk_callhome() {
    hit=$(find /var/tmp -type f -name 'callhome_tmps*' -print 2>/dev/null | head -20)
    if [ -n "$hit" ]; then R="FUND(callhome)"; return 1; else R="OK"; return 0; fi
}

chk_rcpython() {
    f=/flash/nsconfig/rc.netscaler
    [ -r "$f" ] || { R="OK(kein rc.netscaler)"; return 0; }
    if grep -Eiq 'python' "$f" 2>/dev/null; then R="FUND(python in rc)"; return 1; else R="OK"; return 0; fi
}

chk_nobodyproc() {
    hit=$(ps auxww 2>/dev/null | grep '^nobody' | grep -v '/bin/httpd' | grep -v '[g]rep' | head -20)
    if [ -n "$hit" ]; then R="FUND(nobody-proc)"; return 1; else R="OK"; return 0; fi
}

chk_nobodycron() {
    command -v crontab >/dev/null 2>&1 || { R="CHECK(no crontab)"; return 1; }
    hit=$(crontab -u nobody -l 2>/dev/null | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$')
    if [ -n "$hit" ]; then R="FUND(nobody-cron)"; return 1; else R="OK"; return 0; fi
}

run_check() {
    case "$1" in
        fw)         chk_fw ;;
        isn)        chk_isn ;;
        httpdioc)   chk_httpdioc ;;
        shellsuid)  chk_shellsuid ;;
        dotfiles)   chk_dotfiles ;;
        hiddenvpn)  chk_hiddenvpn ;;
        b64logs)    chk_b64logs ;;
        crash)      chk_crash ;;
        callhome)   chk_callhome ;;
        rcpython)   chk_rcpython ;;
        nobodyproc) chk_nobodyproc ;;
        nobodycron) chk_nobodycron ;;
        *) R="CHECK(unbekannter Selektor '$1')"; return 1 ;;
    esac
}

ALL_CHECKS="fw isn httpdioc shellsuid dotfiles hiddenvpn b64logs crash callhome rcpython nobodyproc nobodycron"

case "$SEL" in
    ALL|REPORT)
        OUT="/var/tmp/netscaler-ioc-check_${HOST}.txt"
        : > "$OUT" 2>/dev/null
        # Gate: IOC-Check erst nach Upgrade auf den Ziel-Build ausfuehren
        if ! is_ready; then
            LINE="IOC;$HOST;$READY;GESAMT=UEBERSPRUNGEN(Upgrade 14.1-73.37 ausstehend)"
            printf '%s\n' "$LINE"
            printf '%s\n' "$LINE" >> "$OUT" 2>/dev/null
            logger -p local0.notice -t IOCCHECK "$LINE" 2>/dev/null
            [ "$SEL" = "REPORT" ] && exit 0 || exit 1
        fi
        LINE="IOC;$HOST"
        any=0
        for c in $ALL_CHECKS; do
            run_check "$c"; rc=$?
            LINE="$LINE;$c=$R"
            [ "$rc" -ne 0 ] && any=1
            printf '%s\n' "[$c] $R" >> "$OUT" 2>/dev/null
        done
        [ "$any" -eq 1 ] && LINE="$LINE;GESAMT=PRUEFEN" || LINE="$LINE;GESAMT=SAUBER"
        printf '%s\n' "$LINE"
        printf '%s\n' "$LINE" >> "$OUT" 2>/dev/null
        logger -p local0.notice -t IOCCHECK "$LINE" 2>/dev/null
        if [ "$SEL" = "REPORT" ]; then exit 0; fi
        [ "$any" -eq 1 ] && exit 1 || exit 0
        ;;
    fw)
        # Firmware-/Readiness-Indikator laeuft IMMER (zeigt Upgrade-Stand)
        run_check fw; rc=$?
        LINE="IOC;$HOST;fw=$R"
        printf '%s\n' "$LINE"
        logger -p local0.notice -t IOCCHECK "$LINE" 2>/dev/null
        exit $rc
        ;;
    *)
        # Gate: IOC-Indikatoren erst nach Upgrade auf den Ziel-Build
        if ! is_ready; then
            LINE="IOC;$HOST;$SEL=SKIP_$READY"
            printf '%s\n' "$LINE"
            logger -p local0.notice -t IOCCHECK "$LINE" 2>/dev/null
            exit 1
        fi
        run_check "$SEL"; rc=$?
        LINE="IOC;$HOST;$SEL=$R"
        printf '%s\n' "$LINE"
        logger -p local0.notice -t IOCCHECK "$LINE" 2>/dev/null
        exit $rc
        ;;
esac
