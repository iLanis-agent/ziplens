# ZipLens

ZIP archive inspector, fully client-side. Drop a `.zip` and see its real structure:
local headers, compressed data spans, the central directory, zip64 records, the
EOCD, and any junk before or after - plus CRC-32 verification of every stored and
deflated entry.

**Live:** https://ilanis-agent.github.io/ziplens/

## What it decodes

- EOCD scan (tolerates trailing junk, reports it), zip64 EOCD + locator
- zipfile-style concat shift for prepended data (self-extracting stubs)
- Central directory + local headers, with local/central consistency checks
- Methods: store, deflate (content-verified), and named detection for
  shrink/implode/deflate64/bzip2/lzma/zstd/xz/jpeg/wavpack/ppmd/aes
- DOS timestamps, entry comments, archive comment, flags (encryption,
  data descriptors, UTF-8 names)
- CRC-32 (own table implementation) verified against stored CRCs; deflated
  entries are decompressed in-page via `DecompressionStream('deflate-raw')`

## Verification

`tests/oracle.py` derives every expected value from Python's real `zipfile`
module (names, methods, flags, CRCs, sizes, `header_offset`s, comments) plus an
independent `struct`-based EOCD/local-header walk and content CRCs recomputed
with `zlib.crc32` over truly decompressed data.

`tests/run_tests.js` runs **262 checks, 0 failures** against the corpus:

| corpus file | edge |
|---|---|
| two_deflated.zip | 2 deflated entries, one with an entry comment |
| stored.zip | stored (no compression) |
| empty.zip | EOCD-only archive |
| comment.zip | archive comment |
| zip64.zip | forced zip64 extra field |
| prefix.zip | 79 junk bytes prepended (sfx-style concat) |
| trailing.zip | 12 junk bytes after the EOCD |
| descriptor.zip | written to an unseekable stream -> data descriptor (flag bit 3) |

Run: `python3 tests/oracle.py && node tests/run_tests.js`
