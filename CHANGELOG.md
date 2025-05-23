# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

### Categories each change fall into

* **Added**: for new features.
* **Changed**: for changes in existing functionality.
* **Deprecated**: for soon-to-be removed features.
* **Removed**: for now removed features.
* **Fixed**: for any bug fixes.
* **Security**: in case of vulnerabilities.

## [unreleased]
### Added
- Add function for setting and clearing interface flags.

### Changed
- Bump MSRV to 1.77.
- Upgrade `ipnetwork` dependency from 0.20 to 0.21. This is a breaking change since
  `ipnetwork` is part of the public API.


## [0.6.1] - 2024-10-02
### Added
- Add support for NAT anchors and rules.


## [0.6.0] - 2024-09-04
### Added
- Add support for scrub anchors and rules. Since this modifies the public enums `AnchorKind` and
  `RulesetKind`, it is a breaking change. They have been marked as `non_exhaustive` to prevent
  future additions from being breaking.


## [0.5.0] - 2024-07-24
### Added
- Add function for listing all states created by PF anchor rules.
- Add function for removing individual states created by PF anchor rules.

### Changed
* Upgrade `ipnetwork` dependency from 0.16 to 0.20. This is a breaking change since
  `ipnetwork` is part of the public API.
* Upgrade crate to Rust 2021 edition.
* MSRV bumped to 1.69 due to use of `CStr::from_bytes_until_nul`.
* Replace `error-chain` generated errors with manually implemented error types. This changes
  the public API of the error related types quite significantly. Also the chain of errors
  will be different. But it should be as easy to destructure and handle errors as before,
  and error messages should be at least as informative.

### Removed
* Remove `PoolAddrList::to_palist` from the public API. It should never have been exposed.
* Remove `build_internal` methods on `FilterRuleBuilder` and `RedirectRuleBuilder`.
  This was never supposed to be public, but a side effect of using `derive-builder`.


## [0.4.6] - 2024-04-18
### Added
- Add function for clearing states related to an interface.


## [0.4.5] - 2022-12-28
- Add support for Timex ICMP rules.


## [0.4.4] - 2021-10-08
### Added
- Add `Icmp6Code::Redir` variant.


## [0.4.3] - 2021-10-08
### Fixed
- Fix bug in ICMP `code` field value. It was not possible to have rules *not*
  checking the `code` field. It was always checked to be `0`.


## [0.4.2] - 2021-10-08
### Added
- Add support for matching filter rules against ICMP type/code fields.


## [0.4.1] - 2021-02-23
### Changed
- Upgrade ioctl-sys to 0.6.0. This adds support for Apple Silicon (M1).
- Minimum Rust version is now 1.42.0. A dependency use subslice pattern.


## [0.4.0] - 2020-06-09
### Added
- Add support for user and group IDs to rules.
- Add option to reject packets instead of simply dropping them.

### Changed
- Minimum Rust version is now 1.38.0
- Upgrade publicly re-exported dependency `ipnetwork` to 0.16.0.


## [0.3.0] - 2019-09-13
### Changed
- Upgrade the crate to Rust 2018.
- Upgrade publicly re-exported dependency `ipnetwork` to 0.15.0.
- Minimum Rust version is now 1.32.0


## [0.2.0] - 2018-06-25
### Added
- Travis CI job for the oldest supported Rust version, currently 1.26.0.

### Changed
- Upgrade re-exported dependency ipnetwork to 0.13.
- Upgrade error-chain to 0.12 and re-export it.


## [0.1.1] - 2018-01-08
### Changed
- Removed building the C bindings in build.rs. Instead commit the generated bindings directly in
  the crate. This makes it possible to build the crate on non-macOS and on macOS without Xcode
  installed.


## [0.1.0] - 2017-12-20
### Added
- Initial functionality able to control most parts of the PF firewall on macOS

