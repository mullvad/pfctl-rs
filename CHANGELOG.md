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

