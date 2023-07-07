pub const Handle = packed struct(u32) { bits: u32 };

pub const Event = opaque {
    pub const release = bofEventRelease;
    extern fn bofEventRelease(event: *Event) callconv(.C) void;

    pub fn isComplete(event: *Event) bool {
        return bofEventIsComplete(event) != 0;
    }
    extern fn bofEventIsComplete(event: *Event) callconv(.C) c_int;

    pub const wait = bofEventWait;
    extern fn bofEventWait(event: *Event) callconv(.C) void;
};

pub const CompletionCallback = *const fn (
    bof_handle: Handle,
    run_result: c_int,
    user_context: ?*anyopaque,
) callconv(.C) void;

pub const ArgData = extern struct {
    original: [*]u8 = undefined,
    buffer: [*]u8 = undefined,
    length: i32 = 0,
    size: i32 = 0,
};

pub const load = bofLoad;
extern fn bofLoad(
    bof_name_or_id: [*:0]const u8,
    file_data_ptr: [*]const u8,
    file_data_len: c_int,
    out_bof_handle: *Handle,
) callconv(.C) c_int;

pub const unload = bofUnload;
extern fn bofUnload(bof_handle: Handle) void;

pub const isLoaded = bofIsLoaded;
extern fn bofIsLoaded(bof_handle: Handle) c_int;

pub const run = bofRun;
extern fn bofRun(bof_handle: Handle, arg_data_ptr: ?[*]u8, arg_data_len: c_int) callconv(.C) c_int;

pub const runAsync = bofRunAsync;
extern fn bofRunAsync(
    bof_handle: Handle,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    completion_cb: ?CompletionCallback,
    completion_cb_context: ?*anyopaque,
    out_event: ?**Event,
) callconv(.C) c_int;

/// Returns value returned from bof (zero or greater)
/// Returns negative value when error occurs
pub const loadAndRun = bofLoadAndRun;
extern fn bofLoadAndRun(
    bof_name_or_id: [*:0]const u8,
    file_data_ptr: [*]const u8,
    file_data_len: c_int,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    out_bof_handle: ?*Handle,
) callconv(.C) c_int;

/// Returns zero on success
/// Returns negative value when error occurs
pub const packArg = bofPackArg;
extern fn bofPackArg(data: *ArgData, arg: [*]const u8, arg_len: c_int) callconv(.C) c_int;

pub fn getOutput(bof_handle: Handle) ?[]const u8 {
    var len: c_int = 0;
    const ptr = bofGetOutput(bof_handle, &len);
    if (ptr == null) return null;
    return ptr.?[0..@as(usize, @intCast(len))];
}
extern fn bofGetOutput(bof_handle: Handle, out_output_len: ?*c_int) ?[*:0]const u8;

pub const clearOutput = bofClearOutput;
extern fn bofClearOutput(bof_handle: Handle) void;

/// Returns zero on success
/// Returns negative value when error occurs
pub const initLauncher = bofInitLauncher;
extern fn bofInitLauncher() callconv(.C) c_int;

pub const deinitLauncher = bofDeinitLauncher;
extern fn bofDeinitLauncher() callconv(.C) void;
