# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2019-02-17
### Added
- Code cleanup
- Buffer over-read bug fix
- U2F counter endianness bug fix
- More testing
- Extension interface to U2F and FIDO2
    - Read firmware version
    - Read RNG bytes

## [1.1.1] - 2019-03-01

- This version fixes an incorrect error code returned in U2F.  

## [2.0.0] - 2019-03-01

- Merge of NFC functionality branch
- Bug fix with compiled USB name being too long causing buffer overrun
- Change upper byte of counter from `0xff` to `0x7f` to fix issues with some websites.
