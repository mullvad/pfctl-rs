#!/usr/bin/env sh

# Please always have the latest version of bindgen and rustfmt installed before using this script

# Download the pfvar.h file to generate bindings for from:
# https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pfvar.h

main() {
    os=${OS:-$(uname -s)}
    # Takes inputs from user if provided, otherwise set it to empty and let the script sort it out.
    case $os in
        'Darwin')
            mac_os "${1}" "${2}"
            ;;
        'FreeBSD')
            freebsd "${1}" "${2}"
            ;;
        'OpenBSD')
            openbsd "${1}" "${2}"
            ;;
        *)
            >&2 echo "Unknown or unsupported operating system: '${os}'"
            >&2 echo "Supported operating systems are: 'Darwin' (macOS), 'FreeBSD', 'OpenBSD'"
            >&2 echo "The operating system is autodetected using 'uname -s' or manually defined with \$OS variable"
            exit 1
            ;;
    esac
}

mac_os() {
    SDK_PATH=$(xcodebuild -sdk macosx Path -version)
    # Download pfvar.h if not provided
    if [ -z "${1}" ]; then
        input=./_pfvar_macos.h
        apple_pfvar_download_url="https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/pfvar.h"
        echo "Downloading pfvar.h from ${apple_pfvar_download_url}"
        if ! curl -o "${input}" "${apple_pfvar_download_url}"; then
            >&2 echo "Failed to download pfvar.h"
            exit 1
        fi
    else
        input=${1}
    fi
    output=${2:-./src/ffi/pfvar/macos.rs}
    echo "Using macOS SDK at:"
    echo "    $SDK_PATH"
    echo ""
    bindgen \
        --allowlist-type pf_status \
        --allowlist-type pfioc_rule \
        --allowlist-type pfioc_pooladdr \
        --allowlist-type pfioc_trans \
        --allowlist-type pfioc_states \
        --allowlist-type pfioc_state_kill \
        --allowlist-var PF_.* \
        --allowlist-var PFRULE_.* \
        --default-enum-style rust \
        -o "${output}" "${input}" -- \
        -DPRIVATE \
        -I"$SDK_PATH/usr/include" \
        -I"$SDK_PATH/System/Library/Frameworks/Kernel.framework/Versions/A/Headers"
    rm "$input"
    echo "pfvar.h bindings for macOS has been generated at: ${output}"
}

freebsd() {
    if [ -z "${1}" ]; then
        input=/usr/include/net/pfvar.h
    else
        input=${1}
    fi
    output=${2:-./src/ffi/pfvar/freebsd.rs}
    bindgen \
        --allowlist-type pf_status \
        --allowlist-type pfioc_rule \
        --allowlist-type pfioc_pooladdr \
        --allowlist-type pfioc_trans \
        --allowlist-type pfioc_states \
        --allowlist-type pfioc_state_kill \
        --allowlist-var PF_.* \
        --allowlist-var PFRULE_.* \
        --default-enum-style rust \
        -o "${output}" "${input}"
    rm "${input}"
    echo "pfvar.h bindings for FreeBSD has been generated at: ${output}"
}

openbsd() {
    if [ -z "${1}" ]; then
        input=./_pfvar_wrapper_openbsd.h
        # Need to create a wrapper header because pfvar.h needs if.h to be included first.
        printf "#include <net/if.h>\n#include <net/pfvar.h>" > "${input}"
    else
        input=${1}
    fi
    output=${2:-./src/ffi/pfvar/openbsd.rs}
    # OpenBSD has a weird way of packaging LLVM/Clang. Needs to be manually specified.
    if [ -z "$LIBCLANG_PATH" ]; then
        >&2 echo "\$LIBCLANG_PATH is missing. An LLVM toolchain has to be installed first e.g.: pkg_add llvm17"
        >&2 echo "Then set LIBCLANG_PATH to that LLVM's lib directory (if LLVM 17 is installed):"
        >&2 echo "export LIBCLANG_PATH=/usr/local/llvm17/lib"
        exit 1
    fi
    bindgen \
        --allowlist-type pf_status \
        --allowlist-type pfioc_rule \
        --allowlist-type pfioc_pooladdr \
        --allowlist-type pfioc_trans \
        --allowlist-type pfioc_states \
        --allowlist-type pfioc_state_kill \
        --allowlist-var PF_.* \
        --allowlist-var PFR_.* \
        --allowlist-var PFRULE_.* \
        --default-enum-style rust \
        -o "${output}" "${input}"
    rm "${input}"
    echo "pfvar.h bindings for OpenBSD has been generated at: ${output}"
}

main "$@"
