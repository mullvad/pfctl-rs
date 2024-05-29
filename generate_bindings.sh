#!/usr/bin/env bash

# Please always have the latest version of bindgen and rustfmt installed before using this script

# Download the pfvar.h file to generate bindings for from:
# https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pfvar.h

pfvar_h_path=${1:?"Specify path to pfvar.h as first argument"}

SDK_PATH=$(xcodebuild -sdk macosx Path -version)
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
    -o ./src/ffi/pfvar.rs "$pfvar_h_path" -- \
    -DPRIVATE \
    -I"$SDK_PATH/usr/include" \
    -I"$SDK_PATH/System/Library/Frameworks/Kernel.framework/Versions/A/Headers"
