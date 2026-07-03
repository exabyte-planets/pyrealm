# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project adheres to
[Semantic Versioning].

## [Unreleased]

### Added

- Add `Results.iter_valid()` for reporting and skipping unreadable records in
  damaged result sets.
- Add structural warnings for invalid Realm top references while continuing to
  recover orphan arrays.
- Add recovery guidance to logical-open errors and malformed-data CLI errors.

### Changed

- Decode invalid UTF-8 sequences in damaged Realm string values with Unicode
  replacement characters so the rest of the record remains readable.

### Fixed

- Translate malformed native schemas, record metadata, link targets, and
  Decimal128 values into public Realm errors instead of leaking implementation
  exceptions.
- Close partially initialized native Realm handles when schema loading fails.
- Handle impossibly large string-carving minimums without overflowing the
  regular-expression parser.
- Report malformed structural values as operational CLI errors without a
  traceback.

[Unreleased]: https://github.com/exabyte-planets/pyrealm/commits/main
[Keep a Changelog]: https://keepachangelog.com/en/2.0.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
