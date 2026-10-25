#!/usr/bin/env bash
# Self-test for pactool. Usage: tests/run_tests.sh [path/to/official/unpac.pl]
# If the official Unisoc unpac.pl is given, repacked output is also validated with it.
set -u
cd "$(dirname "$0")/.."
OFFICIAL_PL="${1:-}"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
fail=0; ok() { echo "  ok   $1"; }; bad() { echo "  FAIL $1"; fail=1; }

cc -std=c99 -g -O1 -fsanitize=address,undefined -Wall -Wextra -o "$W/pactool" pactool.c || exit 1
export ASAN_OPTIONS=detect_leaks=0
P="$W/pactool"

python3 tests/make_test_pac.py good "$W/good.pac"
$P verify "$W/good.pac" >/dev/null && ok "independent generator's CRCs verify" || bad "verify good.pac"

$P unpack "$W/good.pac" "$W/out" >/dev/null && ok "unpack" || bad "unpack"
$P pack "$W/out" "$W/re.pac" >/dev/null && cmp -s "$W/good.pac" "$W/re.pac" \
  && ok "unpack -> pack is byte-identical" || bad "round trip differs"

cp "$W/good.pac" "$W/c.pac"; printf '\xff' | dd of="$W/c.pac" bs=1 seek=300000 conv=notrunc 2>/dev/null
$P verify "$W/c.pac" >/dev/null 2>&1 && bad "corruption not detected" || ok "corruption detected"
$P unpack -S "$W/c.pac" "$W/c_out" >/dev/null 2>&1 && ok "-S skips CRC" || bad "-S"

python3 tests/make_test_pac.py evil "$W/evil.pac"
mkdir "$W/sandbox"; $P unpack "$W/evil.pac" "$W/sandbox/out" >/dev/null 2>&1
n=$(find "$W" -name 'evil_*' -o -name 'pactool_evil_b*' | grep -vc "^$W/sandbox/out/")
[ "$n" = 0 ] && [ ! -e /tmp/pactool_evil_b.txt ] && ok "path traversal contained" || bad "path traversal"

if [ -n "$OFFICIAL_PL" ]; then
  d=$(dirname "$OFFICIAL_PL")
  python3 - "$W/out/pac.manifest" <<'EOF'
import re,sys   # official perl cannot cope with empty/unicode names: drop those entries for its check
s=open(sys.argv[1]).read(); parts=re.split(r'(?=\n\[file\])',s)
open(sys.argv[1],'w').write(''.join(p for p in parts if not re.search(r'^id=(OnlyID|Userdata)$',p,re.M)))
EOF
  $P pack "$W/out" "$W/perl_in.pac" >/dev/null
  perl -I"$d" "$OFFICIAL_PL" "$W/perl_in.pac" "$W/perl_out" >/dev/null 2>&1 \
    && cmp -s "$W/perl_out/system.img" "$W/out/system.img" && ok "official unpac.pl accepts repacked PAC (CRCs checked)" \
    || bad "official unpac.pl rejected repacked PAC"
fi
[ $fail = 0 ] && echo "ALL PASSED" || { echo "SOME TESTS FAILED"; exit 1; }
