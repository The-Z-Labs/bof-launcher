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

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    // calling BeaconPrintf function from Beacon's internal API:
    _ = beacon.printf(.output, "hello, bof!\n");

    return 123; // BOF exit code (usually 0 if no error occurs)
}
