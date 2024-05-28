#!/usr/bin/env bash

# Please always have the latest version of bindgen and rustfmt installed before using this script

SDK_PATH=`xcodebuild -sdk macosx Path -version`
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
    -o ./src/ffi/pfvar.rs ./ffi/pfvar.h -- \
    -DPRIVATE \
    -I$SDK_PATH/usr/include \
    -I$SDK_PATH/System/Library/Frameworks/Kernel.framework/Versions/A/Headers
