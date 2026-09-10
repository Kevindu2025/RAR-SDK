rarsdk - RAR / LArc Archive Development Kit
============================================

What it is
----------
A self-contained Windows x64 SDK for archive work, exposing both a
production-grade RAR5 path and a teaching-grade LArc / primitives path
through a single C ABI (rarsdk.dll):

Part 1. RAR5 extraction (official UnRAR 7.23 source under
        unrar/license.txt), wrapped in a clean C API:
        * OpenArchiveEx / ReadHeaderEx / ProcessFile[W]
        * TestArchive / ExtractArchive / IsArchive
        * SetCallback / SetPassword[W]
        * RecoverArchive (Reed-Solomon repair using UnRAR RS16 decoder)

Part 2. RAR5 creation (clean-room writer, store method) with full
        WinRAR 7.23 byte-level interop:
        * RAR5 signature / MAIN / FILE / SERVICE / ENDARC headers
        * vint encoding, CRC32 header checksums
        * BLAKE2sp file hashes (mirror of UnRAR blake2s/blake2sp)
        * AES-256 file encryption (PSWCHECK|HASHMAC, HMAC-SHA256
          transformed CRC32, 16-byte block padding) - verified by
          'rar t -p<password>' from WinRAR 7.23
        * optional header encryption (-hp style)
        * Reed-Solomon recovery records (GF(2^16), ND=1 clone layout)
          with MAIN locator patching - verified by 'rar t', 'rar rv'
          and successful 'rar r' repair of deliberately damaged archives

Part 3. Low-level primitives exposed for advanced users:
        * RAR5 vint encoding/decoding
        * CRC32, BLAKE2sp, BLAKE2spFile
        * Rar5KDF (PBKDF2-HMAC-SHA256 RAR5 triple checkpoint) and
          Rar3KDF (RAR3 SHA-1 x0x40000)
        * RAR5 AES context (RARSDK_AES - encrypt/decrypt CBC state)
        * RS16 GF(2^16) encoder/decoder

Part 4. Reusable compression / crypto primitives (merged from learnarc,
        public-domain teaching implementations):
        * rarsdk_LaSha256[Init/Update/Final] + one-shot
        * rarsdk_LaHmacSha256 (RFC 2104)
        * rarsdk_LaPbkdf2HmacSha256 (RFC 2898, multi-block)
        * rarsdk_LaAesInit + EncryptBlock / DecryptBlock /
          CbcEncrypt / CbcDecrypt (FIPS-197 AES-128/192/256)
        * rarsdk_LaLzhEncode / Decode (LZ77 + canonical Huffman;
          'rar -m1..-m4' family, winSize 64KB..4MB, maxChain 4..256)
        * rarsdk_LaPpmCompress / Decompress (simplified PPM + range
          coder; 'rar -m5' idea; order 1..16)

Part 5. LArc container format (LA v1, merged from learnarc) -
        a self-contained teaching-grade archive format with per-entry
        CRC32 header, store/lzh/ppm methods, and optional RAR5-style
        AES-256 encryption (PSWCHECK + HASHMAC). NOT compatible with
        WinRAR / RAR. Suitable as a reference format or for use cases
        where a simple embeddable archive is sufficient:
        * rarsdk_LArcWriterCreate / AddFile / AddData / AddDir /
          Save / Free
        * rarsdk_LArcReaderOpen / Close / List(cb) / ExtractAll

C++ users can also `#include` the headers under `include/learnarc/`
directly to use the original `learnarc::` C++ namespace API.

Not included (by design / license)
----------------------------------
  * RAR LZ/Huffman/PPMd compression (proprietary). Part 2 supports
    only the "store" method; Part 4's rarsdk_LaLzh* / LaPpm* are
    independent teaching implementations NOT compatible with RAR.

Layout
------
  rarsdk.h                public C API (Parts 1-5)
  unrar_dll_iface.h       UnRAR dll.hpp mirror structs
  rs_internal.h           internal shared header for RAR5 writer
  rs_writer.cpp           RAR5 vint/CRC32/SHA256/PBKDF2/BLAKE2sp primitives
  rs_blake.cpp            BLAKE2sp (mirror of UnRAR blake2s.cpp/blake2sp.cpp)
  rs_aes.cpp              RAR5 AES-256 CBC
  rs_rs16.cpp             RAR5 Reed-Solomon GF(2^16) encoder/decoder
  rs_create.cpp           RAR5 writer (headers, encryption, RR, locator)
  rs_extra.cpp            file helpers (hash a file, etc.)
  rs_bridge.cpp           bridges extraction API to internal UnRAR

  la_sha256.cpp           C wrappers: SHA-256 / HMAC / PBKDF2
  la_aes.cpp              C wrappers: AES block + CBC
  la_lzh.cpp              C wrappers: LZ77 + canonical Huffman
  la_ppm.cpp              C wrappers: PPM + range coder
  la_larc.cpp             C wrappers: LArc container reader/writer

  include/learnarc/       original C++ headers (namespace learnarc)
                          header-only: sha256.hpp / aes.hpp / bitio.hpp /
                          huffman.hpp / lzss.hpp / lzh.hpp / ppm.hpp /
                          arcrypto.hpp / container.hpp

  rarsdk.def              DLL exports (Parts 1-5)
  build_rarsdk.bat        MSVC build script (VS BuildTools, x64)
  test_sdk.c              end-to-end test for RAR5 paths
  test_larc.c             end-to-end test for LArc / primitives paths
  hashfile.c              small CLI: BLAKE2sp+CRC32 of a file
  unrar/                  official UnRAR 7.23 sources (extraction engine)

Build
-----
  Requirements: VS BuildTools 2017+ (cl/link), x64.
  Run: build_rarsdk.bat
  Output: bin\rarsdk.dll + bin\rarsdk.lib

  The script caches objects in obj\; delete obj\ to force full rebuild.

Interop test matrix (WinRAR 7.23 x64, verified 2026-09-08)
----------------------------------------------------------
  RAR5 plain store archive       rar t          all files OK
  RAR5 encrypted files archive   rar t -p***    data + PswCheck + MAC-CRC OK
  RAR5 RR archive                rar t / rv    recovery record 100% OK / clean
  RAR5 damaged RR archive        rar r          file recovered from RR
  SDK self test/extract          -              OK; wrong password => -5

LArc test matrix (test_larc.exe, 2026-09-10)
--------------------------------------------
  SHA-256 / HMAC-SHA256 / PBKDF2                  RFC vectors + roundtrip
  AES-256 ECB / CBC                               FIPS-197 + roundtrip
  LZ77+Huffman 8KB text                           8000 -> 178, decode OK
  PPM order=6, 180B text                          180 -> 129, decode OK
  LArc store: hello.txt                           list + extract OK
  LArc lzh:   8000B                               list + extract OK
  LArc enc:   2048B AES+LZH ("MyPassword")        decrypt + extract OK
  LArc wrong password                             rejected (rc=-5)
  LArc tampered archive (1 byte flipped)          detected (rc=-2)

Scratch / research files (rrparse*.c, rrmk*.c, rrcrc*.c, rrclone.c,
myblake2.c, blake_ref.c, test_*.cpp) are kept for reference; they are
not part of the build.
