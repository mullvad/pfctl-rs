#! /usr/bin/env bash

# Will make sure you have rustfmt at the version in $VERSION, then format all the source code.
# Run with --only-format as the first argument to skip checking rustfmt version.

set -u

VERSION="0.3.2"
INSTALL_CMD="cargo install --vers $VERSION --force rustfmt-nightly"

function correct_rustfmt() {
    if ! which rustfmt; then
        echo "rustfmt is not installed" >&2
        return 1
    fi
    export DYLD_LIBRARY_PATH=$(rustc --print sysroot)/lib
    local installed_version=$(rustfmt --version | cut -d'-' -f1)
    if [[ "$installed_version" != "$VERSION" ]]; then
        echo "Wrong version of rustfmt installed. Expected $VERSION, got $installed_version" >&2
        return 1
    fi
    return 0
}

if [[ "${1:-""}" != "--only-format" ]]; then
    if ! correct_rustfmt; then
        echo "Installing rustfmt $VERSION"
        $INSTALL_CMD
    fi
else
    shift
fi

cargo fmt -- "$@"
