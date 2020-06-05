#!/usr/bin/env bash

# Please always have the latest version of bindgen and rustfmt installed before using this script

SDK_PATH=`xcodebuild -sdk macosx Path -version`
echo "Using macOS SDK at:"
echo "    $SDK_PATH"
echo ""

bindgen \
    --whitelist-type pf_status \
    --whitelist-type pfioc_rule \
    --whitelist-type pfioc_pooladdr \
    --whitelist-type pfioc_trans \
    --whitelist-type pfioc_states \
    --whitelist-type pfioc_state_kill \
    --whitelist-var PF_.* \
    --whitelist-var PFRULE_.* \
    -o ./src/ffi/pfvar.rs ./ffi/pfvar.h -- \
    -DPRIVATE \
    -I$SDK_PATH/usr/include \
    -I$SDK_PATH/System/Library/Frameworks/Kernel.framework/Versions/A/Headers
