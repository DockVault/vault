# axe-core, for the accessibility tests only

`axe.min.js` is axe-core, the accessibility rules engine by Deque Systems, used by
`tests/test_ui_accessibility.py` to check the web app's screens in a browser. It is a test file: it is never
served by the vault and never part of its image (`.dockerignore` leaves `tests/` out).

| | |
|---|---|
| Version | 4.14.0 |
| Source | https://registry.npmjs.org/axe-core/-/axe-core-4.14.0.tgz (the file `package/axe.min.js`) |
| Tarball integrity (npm registry) | `sha512-9WTZxEjsZ7b13TH8JPmbV2z8CHbl80/2hm3XPEG4JgNdQLK81IBRXmSxHfMAOkSqQeRxT/0dwNDz2GOm3zzpcQ==` |
| SHA-256 of `axe.min.js` | `20c09fe157a8a34a30e241aaa1fcdade657734f08ab379ecfbeb7d45cc46e878` |
| Licence | Mozilla Public License 2.0 (`LICENSE`); code bundled inside it under the licences in `LICENSE-3RD-PARTY.txt` |

`tests/test_vendored_axe.py` checks the SHA-256 above, so any change to the file fails until this README and
that test are updated with the new version, source and hash.

To update: take the newest release that is at least two weeks old, download its tarball from the npm registry,
check it against the registry's `dist.integrity`, copy `package/axe.min.js`, `package/LICENSE` and
`package/LICENSE-3RD-PARTY.txt` here, and update the table and the test.
