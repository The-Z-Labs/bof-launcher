//name: "String:name of the BOF"
//description: "String:description of the BOF"
//author: "String:BOF author name"
//tags: 'list of BOF tags (in inline format)'
//OS: 'String:possible values:cross|windows|linux'
//header: 'list of BOF special hints and arguments specification (in inline format)'
//sources:
//    - 'List if URLs to BOF source code'
//    - '...'
//usage: '
// Multiline string: BOF arguments specification
//'
//examples: '
// Multiline string: Examples of BOF usage
//'

// Including internal, builtin API:
const beacon = @import("bof_api").beacon;

// Including Windows WinAPI functions:
//const w32 = @import("bof_api").win32;

// Including POSIX functions:
//const posix = @import("bof_api").posix;

pub export fn go(_: ?[*]u8, _: i32) callconv(.C) u8 {

    // calling BeaconPrintf function from Beacon's internal API:
    _ = beacon.printf(0, "hello, bof!\n");

    return 123; // BOF exit code (usually 0 if no error occurs)
}
