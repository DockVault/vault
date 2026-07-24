# CPython 3.14 security backports

The release image starts from the immutable Python 3.14.6 Alpine image, then replaces two standard
library files with their reviewed versions from CPython's `3.14` branch at commit
`07efb08123ba9367a7107325adb9d5626dca1ca9`.

That snapshot contains the upstream 3.14 security backports for:

- CVE-2026-11940 (`tarfile.py`, commit `79c06bd5c6afa3c440d50faf7ee1b147c8832b4c`)
- CVE-2026-11972 (`tarfile.py`, commit `e86666c9dd256d52d0fbef6feb1ea4a51768fdec`)
- CVE-2026-15308 (`html/parser.py`, commit `07efb08123ba9367a7107325adb9d5626dca1ca9`)

The Docker build verifies the vendored files before copying them over the image's standard library:

| File | SHA-256 |
| --- | --- |
| `Lib/tarfile.py` | `3c8d585a77d7d376aea66e5e11a4d53c2605100d4c05a71b5385ed54bc526f51` |
| `Lib/html/parser.py` | `5c5ed245889135564e75dfed9a47aeb6b4d3e5a2e9614d918a986767e3747539` |
| `PSF-LICENSE.txt` | `b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231` |

The files remain under the Python Software Foundation License included in `PSF-LICENSE.txt`.
