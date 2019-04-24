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

## [2.1.0] - 2019-03-31

WARNING: This update may break previous registrations! This is because we fixed the U2F counter for good (rather than arbitrarily set the upper byte high for backwards-compatibility reasons, which ends up causing other issues).

- Adds hmac-secret extension support. This extension is used for generating 32 or 64 byte symmetric keys using parameters from the platform and secrets on the authenticator. It's used by Windows Hello - - for offline authentication.
- Fix bug in FIDO auth, where setting the pin requires all previous registrations to use pin. Only UV bit needs to be cleared.
- Slightly change serial emulation USB descriptor to make it less abused by Linux Modem Manager.

## [2.2.0] - 2019-04-17

- Fixes the ordering of keys encoded in CBOR maps to be canonical ordering. They previously were not ordered in any particular way and caused issues for Chrome. #170
- Fixes CTAP2 implementation to accept credential IDs created by the CTAP1 implementation. So registering with U2F and later authenticating with FIDO2 should work.

## [2.2.1] - 2019-04-23

- This minor release fixes some small issues. #179, #182
