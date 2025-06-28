const std = @import("std");
const beacon = @import("bof_api").beacon;
const c = @cImport({
    @cInclude("pcap.h");
    @cInclude("netinet/in.h");
    @cInclude("arpa/inet.h");
    @cInclude("net/ethernet.h");
    @cInclude("sys/time.h");
    @cInclude("time.h");
    @cInclude("stdio.h");
});

fn packetHandler(args: [*c]u8, packet_header: [*c]const c.pcap_pkthdr, packet_body: [*c] const u8) callconv(.c) void {
    _ = args;
    _ = packet_body;

    _ = c.printf( "Packet capture length: %d\n", packet_header.*.caplen);
    _ = c.printf( "Packet total length %d\n", packet_header.*.len);
}

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    var errbuf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    var netmask: c.bpf_u_int32 = undefined;
    var srcip: c.bpf_u_int32 = undefined;
    var bpf: c.bpf_program = undefined;

    var parser = beacon.datap{};
    beacon.dataParse(&parser, args, args_len);

    if(beacon.dataExtract(&parser, null)) |interface| {

        // Get network device source IP address and netmask.
        if (c.pcap_lookupnet(interface, &srcip, &netmask, &errbuf) == c.PCAP_ERROR) {
            std.debug.print("Error: {s}\n", .{errbuf});
            return 1;
        }

        _ = beacon.printf(0, "ip: %d %d\n", srcip, netmask);

        // Open the network interface for packet capture
        const handle = c.pcap_open_live(interface, 65535, 1, 1000, &errbuf);
        if (handle == null) {
            std.debug.print("Error: {s}\n", .{errbuf});
            return 2;
        }

        // Convert the packet filter epxression into a packet filter binary.
        if (c.pcap_compile(handle, &bpf, "icmp", 0, netmask) == c.PCAP_ERROR) {
            //std.debug.print("Error: {s}\n", .{c.pcap_geterr(handle)});
            return 3;
        }

        // Bind the packet filter to the libpcap handle.
        if (c.pcap_setfilter(handle, &bpf) == c.PCAP_ERROR) {
            return 4;
        }

        _ = c.pcap_loop(handle, 7, packetHandler, null);

        c.pcap_close(handle);
    }

    return 0;
}
