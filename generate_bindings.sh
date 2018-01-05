#!/usr/bin/env bash

SDK_PATH="/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.13.sdk/"

bindgen \
    --whitelist-type pf_status \
    --whitelist-type pfioc_rule \
    --whitelist-type pfioc_pooladdr \
    --whitelist-type pfioc_trans \
    --whitelist-type pfioc_states \
    --whitelist-type pfioc_state_kill \
    --whitelist-var PF_.* \
    -o ./src/ffi/pfvar.rs ./ffi/pfvar.h -- \
    -DPRIVATE \
    -I$SDK_PATH/usr/include \
    -I$SDK_PATH/System/Library/Frameworks/Kernel.framework/Versions/A/Headers
