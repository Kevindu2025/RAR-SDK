rarsdk - RAR5 Archive Development Kit
====================================

What it is
----------
A self-contained Windows x64 SDK for RAR archives:

  * Extraction / testing / recovery: powered by the official UnRAR 7.23
    source (see unrar/license.txt), wrapped in a clean C API.
  * Archive creation: clean-room RAR5 writer (store method) with full
    WinRAR 7.23 byte-level interop, including:
      - RAR5 signature / MAIN / FILE / SERVICE / ENDARC headers
      - vint encoding, CRC32 header checksums
      - BLAKE2sp file hashes (exact mirror of UnRAR blake2s/blake2sp)
      - AES-256 file encryption (PSWCHECK|HASHMAC flags, HMAC-SHA256
        transformed CRC32, 16-byte block padding) - verified by
        'rar t -p<password>' from WinRAR 7.23
      - optional header encryption (-hp style)
      - Reed-Solomon recovery records (GF(2^16), ND=1 clone layout) with
        MAIN locator patching - verified by 'rar t', 'rar rv' and
        successful 'rar r' repair of deliberately damaged archives

Not included (by design / license)
----------------------------------
  * RAR LZ/Huffman/PPMd compression (proprietary). Creation supports
    only the "store" method; extraction handles all methods.

Layout
------
  rarsdk.h              public C API
  unrar_dll_iface.h     UnRAR dll.hpp mirror structs
  rs_internal.h         internal shared header
  rs_writer.cpp         vint/CRC32/SHA256/PBKDF2/BLAKE2sp primitives
  rs_blake.cpp          BLAKE2sp (mirror of UnRAR blake2s.cpp/blake2sp.cpp)
  rs_aes.cpp            AES-128/256 CBC
  rs_rs16.cpp           Reed-Solomon GF(2^16) encoder
  rs_create.cpp         RAR5 writer (headers, encryption, RR, locator)
  rs_extra.cpp          file helpers (hash a file, etc.)
  rs_bridge.cpp         bridges extraction API to internal UnRAR
  rarsdk.def            DLL exports
  build_rarsdk.bat      MSVC build script (VS BuildTools, x64)
  test_sdk.c            end-to-end test suite (creates archives,
                        verifies with official Rar.exe, repairs, etc.)
  hashfile.c            small CLI: BLAKE2sp+CRC32 of a file
  unrar/                official UnRAR 7.23 sources (extraction engine)

Build
-----
  Requirements: VS BuildTools 2017+ (cl/link), x64.
  Run: build_rarsdk.bat
  Output: bin\rarsdk.dll + bin\rarsdk.lib

  The script caches objects in obj\; delete obj\ to force full rebuild.

Interop test matrix (WinRAR 7.23 x64, verified 2026-09-08)
----------------------------------------------------------
  plain store archive       rar t          all files OK
  encrypted files archive   rar t -p***    data + PswCheck + MAC-CRC OK
  RR archive                rar t / rv    recovery record 100% OK / clean
  damaged RR archive        rar r          file recovered from RR
  SDK self test/extract     -              OK; wrong password => -5

Scratch / research files (rrparse*.c, rrmk*.c, rrcrc*.c, rrclone.c,
myblake2.c, blake_ref.c, test_*.cpp) are kept for reference; they are
not part of the build.
