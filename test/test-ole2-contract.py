#!/usr/bin/env python3
"""
OLE2/CFB reader contract test: diff src/ole2.c against python `olefile` for each
Office fixture given on the command line. Validates (1) the stream count and
(2) byte-exact stream contents — for every stream whose leaf name is plain ASCII
(covers EncryptionInfo [mini-FAT], EncryptedPackage [FAT], Workbook, WordDocument,
0Table/1Table, Current User, PowerPoint Document). The C binary is built from
ole2_contract_test.c.  Usage: python3 test/test-ole2-contract.py <file>...
"""
import os, sys, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, '..', 'john-bleeding-jumbo', 'src')
BIN = '/tmp/ole2_contract_test'

try:
    import olefile
except ImportError:
    print("SKIP: python olefile not installed (pip install --user olefile)")
    sys.exit(0)

def build():
    cc = subprocess.run(['cc', '-O2', '-Wall', '-I', SRC, '-o', BIN,
                         os.path.join(HERE, 'ole2_contract_test.c'),
                         os.path.join(SRC, 'ole2.c')],
                        capture_output=True, text=True)
    if cc.returncode != 0:
        print("BUILD FAILED:\n" + cc.stderr); sys.exit(2)

def c_list(path):
    out = subprocess.run([BIN, path], capture_output=True)
    d = {}
    for line in out.stdout.decode('latin1').splitlines():
        if '\t' in line:
            name, size = line.rsplit('\t', 1)
            d[name] = int(size)
    return d

def c_bytes(path, stream):
    return subprocess.run([BIN, path, stream], capture_output=True).stdout

def main():
    build()
    fails = 0; npass = 0
    for path in sys.argv[1:]:
        if not os.path.exists(path):
            print(f"  ✗ {os.path.basename(path)}: MISSING"); fails += 1; continue
        ole = olefile.OleFileIO(path)
        streams = ['/'.join(s) for s in ole.listdir()]
        clist = c_list(path)
        base = os.path.basename(path)

        # (1) count parity
        if len(streams) == len(clist):
            print(f"  ✓ {base}: stream count {len(streams)}"); npass += 1
        else:
            print(f"  ✗ {base}: count py={len(streams)} c={len(clist)} ({sorted(clist)})"); fails += 1

        # (2) byte-exact for plain-ASCII leaf streams (incl. mini + FAT)
        checked_mini = checked_fat = False
        for full in streams:
            leaf = full.split('/')[-1]
            if not all(32 <= ord(ch) < 127 for ch in leaf):
                continue                      # skip \x05/\x06 control-prefixed names
            want = ole.openstream(full).read()
            got = c_bytes(path, leaf)
            if got == want:
                tag = 'mini' if len(want) < 4096 else 'FAT'
                if len(want) < 4096: checked_mini = True
                else: checked_fat = True
                print(f"  ✓ {base}: {leaf} bytes match ({len(want)}B, {tag})"); npass += 1
            else:
                print(f"  ✗ {base}: {leaf} bytes DIFFER (py={len(want)} c={len(got)})"); fails += 1
        if not (checked_mini or checked_fat):
            print(f"  · {base}: no ASCII streams to byte-check")
    print(f"\nOLE2 contract: PASS {npass}  FAIL {fails}")
    sys.exit(1 if fails else 0)

if __name__ == '__main__':
    main()
