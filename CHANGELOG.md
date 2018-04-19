# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

  - Added logger debug statements for debugging.

## [1.0.2] - 2018-02-08

### Changed

  - Use `Base.url_decode64/1` for decoding the default master key instead of `Base.decode64/1`.

## [1.0.1] - 2018-02-08

### Fixed

  - Base64 decode the default master key before verifying.

## [1.0.0] - 2018-02-08

### Changed

  - Changed `ManifoldcoSignature.verify/6` to take options as the last argument. `:master_key`
    is now an option and defaults to the Manifold public master key.

### Added

  - Add the Manifold public master key for signing.

## [0.0.3] - 2018-02-07

### Added

  - Initial release


[Unreleased]: https://github.com/timberio/odin/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/timberio/odin/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/timberio/odin/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/timberio/odin/compare/v0.0.3...v1.0.0
