#!/bin/bash
###############################################################################
# fetch-office-corpus.sh — download real-world legacy/2007 MS-Office samples
# for the OPTIONAL office corpus phase of test/test-jtr-formats-node.js.
#
# Source: openwall/john-samples (a public test corpus). These files are NOT
# committed to this repo because john-samples carries no license; we fetch them
# on demand for local validation only. The committed, license-clean office
# baseline is test/fixtures/office-agile-2013.docx (self-generated).
#
# Passwords are encoded in each filename as ..._<password>_.<ext> (the test
# reads them from there). Covers $oldoffice$ types 0/1/3/4, the XOR graceful-fail
# path, and 2007-standard $office$. (Legacy .ppt has no public sample, so the
# parse_ppt path is exercised only by its brute-force unit logic, not here.)
#
#   ./test/fetch-office-corpus.sh   # -> test/fixtures/office-corpus/
###############################################################################
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fixtures/office-corpus"
BASE="https://raw.githubusercontent.com/openwall/john-samples/main/Office/Office_Secrets"
mkdir -p "$DIR"
echo '*' > "$DIR/.gitignore"     # never commit these (unlicensed upstream)

# subset: one of each path, passwords in the names
FILES=(
  "Office_2003/2003-Office97-2000_VelvetSweatshop_.xls"                       # typ0 XLS basic RC4
  "Office_2003/2003-Office97-2000_myhovercraftisfullofeels_.doc"             # typ1 DOC legacy RC4
  "Office_2003/2003-RC4-40bit-MS-Base-Crypto-1.0_myhovercraftisfullofeels_.doc"  # typ3 DOC + 2nd block
  "Office_2003/Test-RC4-128bit-MS-Strong-Crypto_myhovercraftisfullofeels_.doc"   # typ4 DOC
  "Office_2003/2003-RC4-40bit-MS-Base-1.0_myhovercraftisfullofeels_.xls"     # typ3 XLS
  "Office_XP/XP-RC4-128bit-strong-crypto_myhovercraftisfullofeels_.xls"      # typ4 XLS
  "Office_2003/Test-weak-XOR_myhovercraftisfullofeels_.doc"                  # XOR -> graceful fail
  "Office_2007/2007-Default_myhovercraftisfullofeels_.docx"                  # 2007-standard $office$
)

for rel in "${FILES[@]}"; do
  name="$(basename "$rel")"
  url="$BASE/$rel"
  # percent-encode spaces just in case
  url="${url// /%20}"
  if curl -fsS -m 30 -o "$DIR/$name" "$url"; then
    echo "  got $name ($(wc -c < "$DIR/$name") bytes)"
  else
    echo "  FAILED $name"
  fi
done
echo "office corpus ready: $DIR"
echo "now run:  node test/test-jtr-formats-node.js"
