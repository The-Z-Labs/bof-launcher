const std = @import("std");
const assert = std.debug.assert;

const print = if (@import("builtin").mode == .Debug) log else dummyLog;

fn dummyLog(_: []const u8, _: anytype) void {}
fn log(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt ++ "\n", args);
}

const BofHandle = packed struct(u32) {
    index: u16 = 0,
    generation: u16 = 0,
};
comptime {
    assert(@sizeOf(BofHandle) == @sizeOf(@import("bofapi").bof.Object));
}

const Bof = struct {
    is_allocated: bool = false,
    is_loaded: bool = false,

    all_sections_mem: ?[]align(page_size) u8 = null,

    entry_point: ?*const fn (arg_data: ?[*]u8, arg_len: i32) callconv(.C) u8 = null,

    fn init() Bof {
        return .{};
    }

    fn deinit(bof: *Bof) void {
        bof.unload();
        bof.* = undefined;
    }

    fn run(bof: *Bof, context: *BofContext, arg_data: ?[]u8) void {
        assert(bof.is_allocated == true);
        assert(bof.is_loaded == true);
        assert(gstate.current_bof_context == null);

        print("Trying to run go()...", .{});

        gstate.current_bof_context = context;
        context.result = bof.entry_point.?(
            if (arg_data) |ad| ad.ptr else null,
            if (arg_data) |ad| @as(i32, @intCast(ad.len)) else 0,
        );
        gstate.current_bof_context = null;

        context.done_event.set();

        print("Returned '{d}' from go().", .{context.result});
    }

    fn load(bof: *Bof, allocator: std.mem.Allocator, file_data: []const u8) !void {
        assert(bof.is_allocated == true);

        bof.unload();
        errdefer {
            bof.unload();
            bof.is_allocated = false;
        }

        bof.is_loaded = true;

        if (@import("builtin").os.tag == .linux) {
            try bof.loadElf(allocator, file_data);
        } else {
            try bof.loadCoff(allocator, file_data);
        }
    }

    fn unload(bof: *Bof) void {
        if (bof.is_loaded) {
            assert(bof.is_allocated == true);

            if (bof.all_sections_mem) |slice| {
                if (@import("builtin").os.tag == .windows) {
                    _ = w32.VirtualFree(slice.ptr, 0, w32.MEM_RELEASE);
                } else if (@import("builtin").os.tag == .linux) {
                    std.os.munmap(slice);
                }
            }

            bof.entry_point = null;
            bof.is_loaded = false;
        }
    }

    fn loadCoff(bof: *Bof, allocator: std.mem.Allocator, file_data: []const u8) !void {
        var parser = std.coff.Coff{
            .data = file_data,
            .is_loaded = false,
            .is_image = false,
            .coff_header_offset = 0,
        };

        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const header = parser.getCoffHeader();
        print("COFF HEADER:", .{});
        print("{any}\n\n", .{header});

        var section_mappings = std.ArrayList([]align(page_size) u8).init(arena);
        defer section_mappings.deinit();

        const section_headers = parser.getSectionHeaders();

        const all_sections_mem = blk: {
            const size = (section_headers.len + 1) * max_section_size;
            const addr = w32.VirtualAlloc(
                null,
                size,
                w32.MEM_COMMIT | w32.MEM_RESERVE | w32.MEM_TOP_DOWN,
                w32.PAGE_EXECUTE_READWRITE,
            );
            break :blk @as([*]align(page_size) u8, @ptrCast(@alignCast(addr)))[0..size];
        };
        bof.all_sections_mem = all_sections_mem;

        const got_base_addr = @intFromPtr(all_sections_mem.ptr);

        var func_addr_to_got_entry = std.AutoHashMap(usize, u32).init(arena);
        defer func_addr_to_got_entry.deinit();

        var section_offset: usize = max_section_size;
        for (section_headers) |section_header| {
            const section_name = parser.getSectionName(&section_header);
            print("SECTION NAME: {!s}", .{section_name});
            print("{any}\n\n", .{section_header});

            if (section_header.size_of_raw_data > 0) {
                const section_data = all_sections_mem[section_offset .. section_offset +
                    section_header.size_of_raw_data];

                std.mem.copy(
                    u8,
                    section_data,
                    file_data[section_header.pointer_to_raw_data..][0..section_header.size_of_raw_data],
                );

                try section_mappings.append(@alignCast(section_data));

                section_offset += max_section_size;
            } else {
                try section_mappings.append(@as([*]u8, undefined)[0..0]);
            }
        }

        const symtab = parser.getSymtab().?;
        const strtab = (try parser.getStrtab()).?;

        for (section_headers, 0..) |section_header, section_index| {
            const section_name = parser.getSectionName(&section_header);
            print("SECTION NAME: {!s} ({d})", .{ section_name, section_index });

            const relocs = @as(
                [*]align(1) const coff.Reloc,
                @ptrCast(file_data[section_header.pointer_to_relocations..]),
            )[0..section_header.number_of_relocations];

            for (relocs) |reloc| {
                const sym = symtab.at(reloc.symbol_table_index, .symbol);
                const sym_name = sym_name: {
                    if (sym.symbol.getName()) |sym_name| {
                        break :sym_name sym_name;
                    } else if (sym.symbol.getNameOffset()) |sym_name_offset| {
                        break :sym_name strtab.get(sym_name_offset);
                    } else {
                        unreachable;
                    }
                };

                print("SYMBOL NAME: {s}", .{sym_name});
                print("{any}", .{reloc});
                print("{any}", .{sym.symbol});

                var maybe_func_addr = gstate.func_lookup.get(sym_name);

                if (maybe_func_addr == null and
                    @intFromEnum(sym.symbol.section_number) == 0 and
                    std.mem.indexOfScalar(u8, sym_name, '$') != null)
                {
                    var it = std.mem.split(u8, sym_name, "$");
                    const dll_name = it.first();

                    assert(!std.mem.eql(u8, dll_name, sym_name));

                    print("Parsing LibName$FuncName symbol:", .{});

                    const dll_name_z = try if (@import("builtin").cpu.arch == .x86)
                        // Skip the '_' prefix and add '0' at the end
                        std.mem.concatWithSentinel(arena, u8, &.{dll_name[1..]}, 0)
                    else
                        // Add '0' at the end
                        std.mem.concatWithSentinel(arena, u8, &.{dll_name[0..]}, 0);
                    defer arena.free(dll_name_z);

                    var it2 = std.mem.split(u8, it.next().?, "@");
                    const func_name_z = try std.mem.concatWithSentinel(
                        arena,
                        u8,
                        &.{it2.first()},
                        0,
                    );
                    defer arena.free(func_name_z);

                    print("LibName is: {s}", .{dll_name_z});
                    print("FuncName is: {s}", .{func_name_z});

                    const dll = if (w32.GetModuleHandleA(dll_name_z)) |hmod|
                        hmod
                    else
                        w32.LoadLibraryA(dll_name_z).?;

                    maybe_func_addr = if (w32.GetProcAddress(dll, func_name_z)) |addr|
                        @intFromPtr(addr)
                    else
                        null;
                }

                if (maybe_func_addr == null and @intFromEnum(sym.symbol.section_number) == 0) {
                    var it = std.mem.split(u8, sym_name, "@");
                    const func_name = it.first();

                    const func_name_z = try if (@import("builtin").cpu.arch == .x86)
                        // Skip the '_' prefix and add '0' at the end
                        std.mem.concatWithSentinel(arena, u8, &.{func_name[1..]}, 0)
                    else
                        // Add '0' at the end
                        std.mem.concatWithSentinel(arena, u8, &.{func_name[0..]}, 0);
                    defer arena.free(func_name_z);

                    const static = struct {
                        const libs = [_][*:0]const u8{
                            "kernel32.dll",
                            "ole32.dll",
                            "user32.dll",
                            "secur32.dll",
                            "advapi32.dll",
                            "ws2_32.dll",
                            //"ntdll.dll",
                            "version.dll",
                            "msvcrt.dll",
                            "shlwapi.dll",
                        };
                    };
                    for (static.libs) |lib| {
                        const dll = if (w32.GetModuleHandleA(lib)) |mod|
                            mod
                        else
                            w32.LoadLibraryA(lib).?;

                        maybe_func_addr = if (w32.GetProcAddress(dll, func_name_z)) |addr|
                            @intFromPtr(addr)
                        else
                            null;
                        if (maybe_func_addr != null) break;
                    }

                    if (maybe_func_addr == null) {
                        maybe_func_addr = if (w32.GetProcAddress(
                            w32.GetModuleHandleA(null).?,
                            func_name_z,
                        )) |addr| @intFromPtr(addr) else null;
                    }
                }

                if (maybe_func_addr == null and @intFromEnum(sym.symbol.section_number) == 0) {
                    print("SYMBOL NAME: {s} NOT FOUND!", .{sym_name});
                    return error.UnknownFunction;
                }

                const addr_p = @intFromPtr(section_mappings.items[section_index].ptr) + reloc.virtual_address;
                const addr_s = if (@intFromEnum(sym.symbol.section_number) > 0)
                    @intFromPtr(section_mappings.items[@intFromEnum(sym.symbol.section_number) - 1].ptr)
                else
                    undefined;

                const addend = std.mem.readIntSliceLittle(
                    i32,
                    section_mappings.items[section_index][reloc.virtual_address..],
                ) + @as(i32, @intCast(sym.symbol.value));

                if (maybe_func_addr != null) {
                    const func_addr = maybe_func_addr.?;

                    const got_entry = if (func_addr_to_got_entry.get(func_addr)) |entry| entry else blk: {
                        const entry = func_addr_to_got_entry.count();
                        if (entry >= max_num_external_functions) {
                            print("Too many external functions used. Consider increasing `max_num_external_functions` constant.", .{});
                            return error.TooManyExternalFunctions;
                        }

                        try func_addr_to_got_entry.put(func_addr, entry);
                        break :blk entry;
                    };

                    const func_map_addr = got_base_addr + got_entry * thunk_trampoline.len;

                    var trampoline = [_]u8{0} ** thunk_trampoline.len;
                    std.mem.copy(u8, trampoline[0..], thunk_trampoline[0..]);
                    std.mem.copy(u8, trampoline[thunk_offset..], std.mem.asBytes(&func_addr));
                    std.mem.copy(
                        u8,
                        @as([*]u8, @ptrFromInt(func_map_addr))[0..thunk_trampoline.len],
                        trampoline[0..],
                    );

                    const addr: i32 = @intCast(
                        @as(isize, @intCast(func_map_addr)) - @as(isize, @intCast(addr_p)) - 4,
                    );

                    @as(*align(1) i32, @ptrFromInt(addr_p)).* = addr;
                } else if (@import("builtin").cpu.arch == .x86_64) {
                    switch (reloc.type) {
                        coff.IMAGE_REL_AMD64_ADDR64 => {
                            const a = std.mem.readIntSliceLittle(
                                u64,
                                section_mappings.items[section_index][reloc.virtual_address..],
                            ) + sym.symbol.value;

                            const addr = addr_s + a;

                            @as(*align(1) u64, @ptrFromInt(addr_p)).* = addr;
                        },
                        coff.IMAGE_REL_AMD64_REL32 => {
                            const addr: i32 = @intCast(
                                @as(isize, @intCast(addr_s)) + addend - @as(isize, @intCast(addr_p)) - 4,
                            );

                            @as(*align(1) i32, @ptrFromInt(addr_p)).* = addr;
                        },
                        coff.IMAGE_REL_AMD64_ADDR32NB => {
                            const addr: i32 = @intCast(
                                @as(isize, @intCast(addr_s)) - @as(isize, @intCast(addr_p)) - 4,
                            );

                            @as(*align(1) i32, @ptrFromInt(addr_p)).* = addr;
                        },
                        else => {},
                    }
                } else if (@import("builtin").cpu.arch == .x86) {
                    switch (reloc.type) {
                        coff.IMAGE_REL_I386_DIR32 => {
                            const addr = @as(i32, @intCast(addr_s)) + addend;

                            @as(*align(1) i32, @ptrFromInt(addr_p)).* = addr;
                        },
                        coff.IMAGE_REL_I386_REL32 => {
                            const addr: i32 = @intCast(
                                @as(isize, @intCast(addr_s)) + addend - @as(isize, @intCast(addr_p)) - 4,
                            );

                            @as(*align(1) i32, @ptrFromInt(addr_p)).* = addr;
                        },
                        else => {},
                    }
                }
                print("", .{});
            }
        }

        var go: ?*const fn (arg_data: ?[*]u8, arg_len: i32) callconv(.C) u8 = null;
        var symbol_index: u32 = 0;
        while (symbol_index < header.number_of_symbols) : (symbol_index += 1) {
            const sym = symtab.at(symbol_index, .symbol);
            const sym_name = sym_name: {
                if (sym.symbol.getName()) |sym_name| {
                    break :sym_name sym_name;
                } else if (sym.symbol.getNameOffset()) |sym_name_offset| {
                    break :sym_name strtab.get(sym_name_offset);
                } else {
                    unreachable;
                }
            };
            if ((sym_name.len == 2 and sym_name[0] == 'g' and sym_name[1] == 'o') or // 64-bit
                (sym_name.len == 3 and sym_name[0] == '_' and sym_name[1] == 'g' and sym_name[2] == 'o')) // 32-bit
            {
                const section_index = @intFromEnum(sym.symbol.section_number) - 1;
                print("go() section index: {d}", .{section_index});
                go = @as(
                    @TypeOf(go),
                    @ptrFromInt(@intFromPtr(section_mappings.items[section_index].ptr) + sym.symbol.value),
                );
                break;
            }
        }

        if (go) |_| {
            print("go() FOUND.", .{});
        } else {
            print("go() NOT FOUND.", .{});
            return error.GoFuncNotFound;
        }

        bof.entry_point = go;
    }

    fn loadElf(bof: *Bof, allocator: std.mem.Allocator, file_data: []const u8) !void {
        const os = std.os;

        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var section_headers = std.ArrayList(std.elf.Elf64_Shdr).init(arena);
        defer section_headers.deinit();

        var section_mappings = std.ArrayList([]align(page_size) u8).init(arena);
        defer section_mappings.deinit();

        var symbol_table: []const std.elf.Sym = undefined;
        var string_table: []const u8 = undefined;

        var file_data_stream = std.io.fixedBufferStream(file_data);

        const elf_hdr = try std.elf.Header.read(&file_data_stream);
        print("Number of Sections: {d}", .{elf_hdr.shnum});

        // Load all section headers.
        {
            var section_headers_iter = elf_hdr.section_header_iterator(&file_data_stream);
            while (try section_headers_iter.next()) |section| {
                try section_headers.append(section);
            }
        }

        const all_sections_mem = try os.mmap(
            null,
            (1 + section_headers.items.len) * max_section_size,
            os.PROT.READ | os.PROT.WRITE | os.PROT.EXEC,
            os.MAP.PRIVATE | os.MAP.ANONYMOUS,
            -1,
            0,
        );
        bof.all_sections_mem = all_sections_mem;

        const got = all_sections_mem[0 .. max_num_external_functions * thunk_trampoline.len];

        var func_addr_to_got_entry = std.AutoHashMap(usize, u32).init(arena);
        defer func_addr_to_got_entry.deinit();

        var map_offset: usize = max_section_size;
        for (section_headers.items, 0..) |section, section_index| {
            print("Section Index: {d}", .{section_index});
            print("\tName is {d}", .{section.sh_name});
            print("\tFlags are 0x{x}", .{section.sh_flags});
            print("\tType is 0x{x}", .{section.sh_type});
            print("\tSize is {d}", .{section.sh_size});
            print("\tEntSize is {d}", .{section.sh_entsize});
            print("\tOffset is 0x{x}", .{section.sh_offset});
            print("\tAddr is 0x{x}", .{section.sh_addr});
            print("\tLink is {d}", .{section.sh_link});
            print("\tInfo is {d}", .{section.sh_info});

            const section_offset = @as(usize, @intCast(section.sh_offset));
            const section_size = @as(usize, @intCast(section.sh_size));

            if ((section.sh_type == std.elf.SHT_PROGBITS or
                section.sh_type == std.elf.SHT_NOBITS or
                section.sh_type == (std.elf.SHT_PROGBITS | std.elf.SHT_LOPROC)) and section.sh_size > 0)
            {
                const img = all_sections_mem[map_offset .. map_offset + section_size];

                try section_mappings.append(@alignCast(img));

                std.mem.copy(u8, img, file_data[section_offset..][0..section_size]);

                map_offset += max_section_size;
            } else {
                try section_mappings.append(@as([*]u8, undefined)[0..0]);
            }

            switch (section.sh_type) {
                std.elf.SHT_STRTAB => {
                    var section_string_table = file_data[section_offset..][0..section_size];
                    print("\t\tString Table: {s}", .{section_string_table});
                },
                std.elf.SHT_SYMTAB => {
                    symbol_table = @as(
                        [*]const std.elf.Sym,
                        @ptrCast(@alignCast(&file_data[section_offset])),
                    )[0..@divExact(section_size, @as(usize, @intCast(section.sh_entsize)))];

                    const link = &section_headers.items[section.sh_link];
                    const link_offset = @as(usize, @intCast(link.sh_offset));
                    const link_size = @as(usize, @intCast(link.sh_size));
                    string_table = file_data[link_offset..][0..link_size];

                    print("\t\tSymbol Table", .{});
                    print("\t\tString Table: {s}", .{string_table});
                },
                else => {
                    print("\t\tCase Not Handled", .{});
                },
            }
        }

        const sht_rel_type = if (@sizeOf(usize) == 8) std.elf.SHT_RELA else std.elf.SHT_REL;
        const ElfRel = if (@sizeOf(usize) == 8) std.elf.Rela else std.elf.Rel;

        for (section_headers.items, 0..) |section, section_index| {
            const section_offset = @as(usize, @intCast(section.sh_offset));
            const section_size = @as(usize, @intCast(section.sh_size));

            if (section.sh_type == std.elf.SHT_RELA) {
                print("\tSection type: SHT_RELA", .{});
            } else if (section.sh_type == std.elf.SHT_REL) {
                print("\tSection type: SHT_REL", .{});
            }

            if (section.sh_type == sht_rel_type) {
                print("\tENTRIES (Section Index: {d})", .{section_index});

                const relocs = @as(
                    [*]const ElfRel,
                    @ptrCast(@alignCast(&file_data[section_offset])),
                )[0..@divExact(section_size, @sizeOf(ElfRel))];

                for (relocs) |reloc| {
                    const symbol = &symbol_table[reloc.r_sym()];

                    const addr_p = @intFromPtr(section_mappings.items[section.sh_info].ptr) + reloc.r_offset;
                    const addr_s = @intFromPtr(section_mappings.items[symbol.st_shndx].ptr) + symbol.st_value;
                    const addend = if (@sizeOf(usize) == 4)
                        @as(*align(1) isize, @ptrFromInt(addr_p)).*
                    else
                        reloc.r_addend;

                    const reloc_str = @as([*:0]const u8, @ptrCast(&string_table[symbol.st_name]));
                    print("\t\tSymbol: {s}", .{reloc_str});
                    print("\t\tReloc type: {d}", .{reloc.r_type()});
                    print("\t\tSymbol Value: 0x{x}", .{symbol.st_value});
                    print("\t\tShndx: 0x{x}", .{symbol.st_shndx});
                    print("\t\tInfo: 0x{x}", .{reloc.r_info});
                    print("\t\tOffset: 0x{x}", .{reloc.r_offset});
                    print("\t\tAddend: 0x{x}", .{addend});
                    print("\t\taddr_p: 0x{x}", .{addr_p});
                    print("\t\taddr_s: 0x{x}", .{addr_s});

                    if (symbol.st_shndx == 0 and reloc.r_type() == 0xa and @import("builtin").cpu.arch == .x86) {
                        // EXTERNAL PROCEDURE CALLS (x86 special case)

                        // _GLOBAL_OFFSET_TABLE_
                        // GOT + A - P

                        const relative_offset: i32 = @intCast(
                            @as(i64, @intCast(@intFromPtr(got.ptr))) + addend - @as(i64, @intCast(addr_p)),
                        );

                        @as(*align(1) i32, @ptrFromInt(addr_p)).* = relative_offset;
                    } else if (symbol.st_shndx == 0 and reloc.r_type() != 0) {
                        // EXTERNAL PROCEDURE CALLS (all archs)

                        const func_name = reloc_str[0..std.mem.len(reloc_str)];
                        const maybe_func_ptr = gstate.func_lookup.get(func_name);

                        if (maybe_func_ptr) |func_ptr| {
                            print("\t\tNot defined in the obj: {s} 0x{x}", .{ func_name, func_ptr });
                        } else {
                            print("\t\tFailed to find function {s}", .{func_name});
                            return error.UnknownFunction;
                        }
                        const func_ptr = maybe_func_ptr.?;

                        const got_entry = if (func_addr_to_got_entry.get(func_ptr)) |entry| entry else blk: {
                            const entry = func_addr_to_got_entry.count();
                            if (entry >= max_num_external_functions) {
                                print("Too many external functions used. Consider increasing `max_num_external_functions` constant.", .{});
                                return error.TooManyExternalFunctions;
                            }

                            try func_addr_to_got_entry.put(func_ptr, entry);
                            break :blk entry;
                        };

                        const a1 = @intFromPtr(got.ptr) + got_entry * thunk_trampoline.len;

                        var trampoline = [_]u8{0} ** thunk_trampoline.len;
                        std.mem.copy(u8, trampoline[0..], thunk_trampoline[0..]);
                        std.mem.copy(u8, trampoline[thunk_offset..], std.mem.asBytes(&func_ptr));
                        std.mem.copy(u8, @as([*]u8, @ptrFromInt(a1))[0..thunk_trampoline.len], trampoline[0..]);

                        switch (@import("builtin").cpu.arch) {
                            .aarch64 => {
                                // DOCS: https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst
                                assert(reloc.r_type() == R_AARCH64_CALL26 or reloc.r_type() == R_AARCH64_JUMP26);

                                const relative_offset = (@as(
                                    i32,
                                    @intCast(@as(i64, @intCast(a1)) + addend - @as(i64, @intCast(addr_p))),
                                ) & 0x0fff_ffff) >> 2;

                                // 0x94000000 BL (branch linked)
                                // 0x14000000 B (branch)
                                @as(*align(1) u32, @ptrFromInt(addr_p)).* =
                                    @as(u32, if (reloc.r_type() == R_AARCH64_CALL26) 0x94000000 else 0x14000000) |
                                    @as(u32, @bitCast(relative_offset));
                            },
                            .arm => {
                                // DOCS: https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst
                                assert(reloc.r_type() == R_ARM_CALL or reloc.r_type() == R_ARM_JUMP24);

                                const encoding = @as(*align(1) i32, @ptrFromInt(addr_p)).*;
                                const a: i32 = @intCast(@as(i26, @intCast(encoding & 0x00_ff_ff_ff)) << 2);

                                const relative_offset = @as(
                                    i32,
                                    @intCast(@as(i64, @intCast(a1)) + a - @as(i64, @intCast(addr_p))),
                                );

                                // 0xeb000000 BL (branch linked)
                                // 0xea000000 B (branch)
                                @as(*align(1) u32, @ptrFromInt(addr_p)).* =
                                    @as(u32, if (reloc.r_type() == R_ARM_CALL) 0xeb000000 else 0xea000000) |
                                    @as(u32, @bitCast((relative_offset & 0x03fffffe) >> 2));
                            },
                            else => {
                                const relative_offset: i32 =
                                    @intCast(@as(i64, @intCast(a1)) + addend - @as(i64, @intCast(addr_p)));

                                @as(*align(1) u32, @ptrFromInt(addr_p)).* = @as(u32, @bitCast(relative_offset));
                            },
                        }
                    } else if ((section.sh_flags & std.elf.SHF_INFO_LINK) != 0 and
                        @import("builtin").cpu.arch == .aarch64)
                    {
                        // RELOCATIONS FOR AARCH64
                        // DOCS: https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst

                        switch (reloc.r_type()) {
                            R_AARCH64_ADR_PREL_PG_HI21 => {
                                const s_plus_a_page: i64 = (@as(i64, @intCast(addr_s)) + addend) & ~@as(i64, 0xfff);
                                const p_page: i64 = @as(i64, @intCast(addr_p)) & ~@as(i64, 0xfff);

                                const pc_offset_21: i64 = ((s_plus_a_page - p_page) & 0x0000_0001_ffff_f000) >> 12;
                                const pc_offset_19_hi: u32 = @intCast((pc_offset_21 & 0x0000_0000_001f_fffc) << 3);
                                const pc_offset_2_lo: u32 = @intCast((pc_offset_21 & 0x0000_0000_0000_0003) << 29);

                                var encoding = @as(*align(1) u32, @ptrFromInt(addr_p)).*;
                                encoding = encoding | pc_offset_19_hi | pc_offset_2_lo;
                                @as(*align(1) u32, @ptrFromInt(addr_p)).* = encoding;
                            },
                            R_AARCH64_ADD_ABS_LO12_NC => {
                                const s_plus_a: i64 = @as(i64, @intCast(addr_s)) + addend;
                                const imm: u32 = @as(u32, @intCast(s_plus_a & 0xfff)) << 10;

                                var encoding = @as(*align(1) u32, @ptrFromInt(addr_p)).*;
                                encoding = encoding | imm;
                                @as(*align(1) u32, @ptrFromInt(addr_p)).* = encoding;
                            },
                            R_AARCH64_CALL26 => unreachable,
                            R_AARCH64_JUMP26 => unreachable,
                            R_AARCH64_ABS64 => {
                                const relative_offset = @as(i64, @intCast(addr_s)) + addend;

                                @as(*align(1) i64, @ptrFromInt(addr_p)).* = relative_offset;
                            },
                            R_AARCH64_PREL32 => {
                                const relative_offset = @as(
                                    i32,
                                    @intCast(@as(i64, @intCast(addr_s)) + addend - @as(i64, @intCast(addr_p))),
                                );

                                @as(*align(1) i32, @ptrFromInt(addr_p)).* = relative_offset;
                            },
                            R_AARCH64_LDST8_ABS_LO12_NC => {
                                const s_plus_a: i64 = @as(i64, @intCast(addr_s)) + addend;
                                const imm: u32 = @as(u32, @intCast(s_plus_a & 0xfff)) << 10;

                                var encoding = @as(*align(1) u32, @ptrFromInt(addr_p)).*;
                                encoding = encoding | imm;
                                @as(*align(1) u32, @ptrFromInt(addr_p)).* = encoding;
                            },
                            R_AARCH64_LDST16_ABS_LO12_NC => {
                                const s_plus_a: i64 = @as(i64, @intCast(addr_s)) + addend;
                                const imm: u32 = @as(u32, @intCast(s_plus_a & 0xffe)) << 9;

                                var encoding = @as(*align(1) u32, @ptrFromInt(addr_p)).*;
                                encoding = encoding | imm;
                                @as(*align(1) u32, @ptrFromInt(addr_p)).* = encoding;
                            },
                            R_AARCH64_LDST32_ABS_LO12_NC => {
                                const s_plus_a: i64 = @as(i64, @intCast(addr_s)) + addend;
                                const imm: u32 = @as(u32, @intCast(s_plus_a & 0xffc)) << 8;

                                var encoding = @as(*align(1) u32, @ptrFromInt(addr_p)).*;
                                encoding = encoding | imm;
                                @as(*align(1) u32, @ptrFromInt(addr_p)).* = encoding;
                            },
                            R_AARCH64_LDST64_ABS_LO12_NC => {
                                const s_plus_a: i64 = @as(i64, @intCast(addr_s)) + addend;
                                const imm: u32 = @as(u32, @intCast(s_plus_a & 0xff8)) << 7;

                                var encoding = @as(*align(1) u32, @ptrFromInt(addr_p)).*;
                                encoding = encoding | imm;
                                @as(*align(1) u32, @ptrFromInt(addr_p)).* = encoding;
                            },
                            R_AARCH64_LDST128_ABS_LO12_NC => {
                                const s_plus_a: i64 = @as(i64, @intCast(addr_s)) + addend;
                                const imm: u32 = @as(u32, @intCast(s_plus_a & 0xff0)) << 6;

                                var encoding = @as(*align(1) u32, @ptrFromInt(addr_p)).*;
                                encoding = encoding | imm;
                                @as(*align(1) u32, @ptrFromInt(addr_p)).* = encoding;
                            },
                            else => {},
                        }
                    } else if ((section.sh_flags & std.elf.SHF_INFO_LINK) != 0 and
                        @import("builtin").cpu.arch == .arm)
                    {
                        // RELOCATIONS FOR ARM
                        // DOCS: https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst

                        switch (reloc.r_type()) {
                            R_ARM_REL32 => {
                                const relative_offset: i32 =
                                    @intCast(@as(i64, @intCast(addr_s)) + addend - @as(i64, @intCast(addr_p)));

                                @as(*align(1) i32, @ptrFromInt(addr_p)).* = relative_offset;
                            },
                            R_ARM_ABS32 => {
                                const relative_offset: i32 = @intCast(@as(i64, @intCast(addr_s)) + addend);

                                @as(*align(1) i32, @ptrFromInt(addr_p)).* = relative_offset;
                            },
                            R_ARM_CALL, R_ARM_JUMP24 => {
                                const encoding = @as(*align(1) i32, @ptrFromInt(addr_p)).*;
                                const a: i32 = @intCast(@as(i26, @intCast(encoding & 0x00_ff_ff_ff)) << 2);

                                const relative_offset: i32 =
                                    @intCast(@as(i64, @intCast(addr_s)) + a - @as(i64, @intCast(addr_p)));

                                // 0xeb000000 BL (branch linked)
                                // 0xea000000 B (branch)
                                @as(*align(1) u32, @ptrFromInt(addr_p)).* =
                                    @as(u32, if (reloc.r_type() == R_ARM_CALL) 0xeb000000 else 0xea000000) |
                                    @as(u32, @bitCast((relative_offset & 0x03fffffe) >> 2));
                            },
                            R_ARM_PREL31 => {},
                            else => unreachable,
                        }
                    } else if ((section.sh_flags & std.elf.SHF_INFO_LINK) != 0 and
                        @import("builtin").cpu.arch == .x86_64)
                    {
                        // RELOCATIONS FOR X86_64

                        switch (reloc.r_type()) {
                            0x1 => {
                                // R_X86_64_64 (0x1)

                                @as(*align(1) usize, @ptrFromInt(addr_p)).* =
                                    @as(usize, @intCast(@as(u64, @bitCast(@as(i64, @intCast(addr_s)) + addend))));
                            },
                            0x2, 0x4 => {
                                // R_X86_64_PC32 (0x2)
                                // R_X86_64_PLT32 (0x4)

                                const relative_offset: i32 =
                                    @intCast(@as(i64, @intCast(addr_s)) + addend - @as(i64, @intCast(addr_p)));

                                @as(*align(1) i32, @ptrFromInt(addr_p)).* = relative_offset;
                            },
                            else => {},
                        }
                    } else if ((section.sh_flags & std.elf.SHF_INFO_LINK) != 0 and
                        @import("builtin").cpu.arch == .x86)
                    {
                        // RELOCATIONS FOR X86

                        switch (reloc.r_type()) {
                            0x1 => {
                                // R_X86_64_64 (0x1)

                                @as(*align(1) usize, @ptrFromInt(addr_p)).* =
                                    @as(usize, @intCast(@as(u64, @bitCast(@as(i64, @intCast(addr_s)) + addend))));
                            },
                            0x9 => {
                                // S + A - GOT
                                const relative_offset: i32 = @intCast(
                                    @as(i64, @intCast(addr_s)) + addend - @as(i64, @intCast(@intFromPtr(got.ptr))),
                                );

                                @as(*align(1) i32, @ptrFromInt(addr_p)).* = relative_offset;
                            },
                            else => {},
                        }
                    }
                    print("\t\t-------------------------------------------------", .{});
                }
            }
        }

        // Print all symbols; get pointer to `go()`.
        print("SYMBOLS", .{});
        var go: ?*const fn (arg_data: ?[*]u8, arg_len: i32) callconv(.C) u8 = null;
        for (symbol_table) |sym| {
            if (sym.st_shndx != 0 and sym.st_size != 0 and sym.st_shndx < section_headers.items.len) {
                const name = @as([*:0]const u8, @ptrCast(&string_table[sym.st_name]));
                print(
                    "\tName: {s: <50} Address(real): 0x{x}",
                    .{ name, @intFromPtr(section_mappings.items[sym.st_shndx].ptr) + sym.st_value },
                );
                if (name[0] == 'g' and name[1] == 'o' and name[2] == 0) {
                    go = @as(
                        @TypeOf(go),
                        @ptrFromInt(@intFromPtr(section_mappings.items[sym.st_shndx].ptr) + sym.st_value),
                    );
                }
            }
        }
        if (go) |_| {
            print("go() FOUND.", .{});
        } else {
            print("go() NOT FOUND.", .{});
            return error.GoFuncNotFound;
        }

        bof.entry_point = go;
    }
};

const BofPool = struct {
    const max_num_bofs = 64;

    bofs: []Bof,
    generations: []u16,

    fn init(allocator: std.mem.Allocator) BofPool {
        return .{
            .bofs = blk: {
                var bofs = allocator.alloc(Bof, max_num_bofs + 1) catch @panic("OOM");
                for (bofs) |*bof| bof.* = Bof.init();
                break :blk bofs;
            },
            .generations = blk: {
                var generations = allocator.alloc(u16, max_num_bofs + 1) catch @panic("OOM");
                for (generations) |*gen| gen.* = 0;
                break :blk generations;
            },
        };
    }

    fn deinit(pool: *BofPool, allocator: std.mem.Allocator) void {
        for (pool.bofs) |*bof| bof.deinit();
        allocator.free(pool.bofs);
        allocator.free(pool.generations);
        pool.* = undefined;
    }

    fn allocateBofHandle(pool: BofPool) BofHandle {
        var slot_idx: u32 = 1;
        while (slot_idx <= max_num_bofs) : (slot_idx += 1) {
            if (pool.bofs[slot_idx].is_allocated == false)
                break;
        }
        assert(slot_idx <= max_num_bofs);

        pool.bofs[slot_idx].is_allocated = true;
        return .{
            .index = @as(u16, @intCast(slot_idx)),
            .generation = blk: {
                pool.generations[slot_idx] += 1;
                break :blk pool.generations[slot_idx];
            },
        };
    }

    fn unloadBofAndDeallocateHandle(pool: BofPool, handle: BofHandle) void {
        if (pool.getBofPtrIfValid(handle)) |bof| {
            bof.unload();
            bof.is_allocated = false;
        }
    }

    fn isBofValid(pool: BofPool, handle: BofHandle) bool {
        return handle.index > 0 and
            handle.index <= max_num_bofs and
            handle.generation > 0 and
            handle.generation == pool.generations[handle.index] and
            pool.bofs[handle.index].is_allocated;
    }

    fn getBofPtrIfValid(pool: BofPool, handle: BofHandle) ?*Bof {
        if (pool.isBofValid(handle)) {
            return &pool.bofs[handle.index];
        }
        return null;
    }
};

const BofArgs = extern struct {
    original: ?[*]u8 = null,
    buffer: ?[*]u8 = null,
    length: i32 = 0,
    size: i32 = 0,

    blob: ?[*]u8 = null,
    const blob_size = 128;
};

pub export fn bofArgsInit(
    out_args: **@import("bofapi").bof.Args,
) callconv(.C) c_int {
    const args = gstate.allocator.?.create(BofArgs) catch return -1;
    args.* = .{};
    out_args.* = @ptrCast(args);
    return 0;
}

pub export fn bofArgsRelease(
    args: *@import("bofapi").bof.Args,
) callconv(.C) void {
    const bof_args = @as(*BofArgs, @ptrCast(@alignCast(args)));
    if (bof_args.blob) |b| gstate.allocator.?.free(b[0..BofArgs.blob_size]);
    gstate.allocator.?.destroy(bof_args);
}

pub export fn bofArgsBegin(
    args: *@import("bofapi").bof.Args,
) callconv(.C) void {
    const bof_args = @as(*BofArgs, @ptrCast(@alignCast(args)));
    if (bof_args.blob) |b| gstate.allocator.?.free(b[0..BofArgs.blob_size]);
    bof_args.* = .{};
}

pub export fn bofArgsEnd(
    args: *@import("bofapi").bof.Args,
) callconv(.C) void {
    const bof_args = @as(*BofArgs, @ptrCast(@alignCast(args)));
    if (bof_args.blob != null) {
        bof_args.size = bof_args.size - bof_args.length;
        const len = bof_args.size - 4;
        std.mem.copy(u8, bof_args.original.?[0..4], std.mem.asBytes(&len));
    }
}

pub export fn bofArgsGetBuffer(
    args: *@import("bofapi").bof.Args,
) callconv(.C) ?[*]u8 {
    const bof_args = @as(*BofArgs, @ptrCast(@alignCast(args)));
    return bof_args.original;
}

pub export fn bofArgsGetBufferSize(
    args: *@import("bofapi").bof.Args,
) callconv(.C) c_int {
    const bof_args = @as(*BofArgs, @ptrCast(@alignCast(args)));
    return bof_args.size;
}

pub export fn bofArgsAdd(
    args: *@import("bofapi").bof.Args,
    arg: [*]const u8,
    arg_size: c_int,
) callconv(.C) c_int {
    if (!gstate.is_valid) return -1;
    if (arg_size < 1) return -1;

    const allowed_types = [_][]const u8{
        "short", "s",
        "int",   "i",
        "str",   "z",
        "wstr",  "Z",
        "file",  "b",
    };

    const params = @as(*BofArgs, @ptrCast(@alignCast(args)));

    if (params.blob == null) {
        const blob = gstate.allocator.?.alloc(u8, BofArgs.blob_size) catch return -1;

        params.original = blob.ptr;
        params.buffer = blob.ptr + 4;
        params.length = @intCast(blob.len - 4);
        params.size = @intCast(blob.len);
        params.blob = blob.ptr;
    }

    var sArg = arg[0..@intCast(arg_size)];
    var sArg_type: []const u8 = "str";

    var iter = std.mem.tokenizeAny(u8, sArg, ":");

    // get first element or return if argument was empty
    const prefix = iter.next() orelse return -1;

    // delimeter (:) was found, check if known type was provided
    if (!std.mem.eql(u8, prefix, sArg)) {
        for (allowed_types) |t| {
            if (std.mem.eql(u8, prefix, t)) {
                sArg_type = prefix;

                // remove prefix from the argument:
                sArg = std.mem.trimLeft(u8, sArg, sArg_type);
                sArg = std.mem.trimLeft(u8, sArg, ":");
                break;
            }
        }
    }

    // argument length after removing prefix:
    const arg_len = @as(i32, @intCast(sArg.len));

    if (std.mem.eql(u8, sArg_type, "str") or std.mem.eql(u8, sArg_type, "z")) {
        // check if we have space for: len(i32) | u8 * arg_len | \0
        if (arg_len > params.length - 5) {
            return -1;
        }
        print("Str param: {s} {d}", .{ sArg, sArg.len });

        const arg_len_w0 = arg_len + 1;
        std.mem.copy(u8, params.buffer.?[0..4], std.mem.asBytes(&arg_len_w0));
        params.length -= 4;
        params.buffer.? += 4;

        std.mem.copy(u8, params.buffer.?[0..@intCast(arg_len)], sArg);
        params.length -= arg_len;
        params.buffer.? += @as(usize, @intCast(arg_len));

        params.buffer.?[0] = 0;
        params.length -= 1;
        params.buffer.? += @as(usize, @intCast(1));
    } else if (std.mem.eql(u8, sArg_type, "int") or std.mem.eql(u8, sArg_type, "i")) {
        const numArg = std.fmt.parseUnsigned(u32, sArg, 10) catch return -1;

        print("Int param: {s} {d}", .{ sArg, sArg.len });

        if (arg_len > params.length)
            return -1;

        std.mem.copy(u8, params.buffer.?[0..4], std.mem.asBytes(&numArg));
        params.length -= 4;
        params.buffer.? += 4;
    } else if (std.mem.eql(u8, sArg_type, "short") or std.mem.eql(u8, sArg_type, "s")) {
        const numArg = std.fmt.parseUnsigned(u16, sArg, 10) catch return -1;

        print("Short param: {s} {d}", .{ sArg, sArg.len });

        if (arg_len > params.length)
            return -1;

        std.mem.copy(u8, params.buffer.?[0..2], std.mem.asBytes(&numArg));
        params.length -= 2;
        params.buffer.? += 2;
    }
    // TODO: add wstr (wide chars) support

    return 0;
}

pub export fn bofObjectInitFromMemory(
    file_data_ptr: [*]const u8,
    file_data_len: c_int,
    out_bof_handle: ?*BofHandle,
) callconv(.C) c_int {
    if (out_bof_handle == null) return -1;

    const res = bofLauncherInit();
    if (res < 0) return res;

    var bof_handle = gstate.bof_pool.allocateBofHandle();
    var bof = gstate.bof_pool.getBofPtrIfValid(bof_handle).?;

    bof.load(gstate.allocator.?, file_data_ptr[0..@as(usize, @intCast(file_data_len))]) catch {
        print("Failed to load BOF. Aborting.", .{});
        return -1;
    };

    out_bof_handle.?.* = bof_handle;
    return 0;
}

pub export fn bofObjectRelease(bof_handle: BofHandle) callconv(.C) void {
    if (!gstate.is_valid) return;

    gstate.bof_pool.unloadBofAndDeallocateHandle(bof_handle);
}

pub export fn bofObjectIsValid(bof_handle: BofHandle) callconv(.C) c_int {
    if (!gstate.is_valid) return 0;

    return @intFromBool(gstate.bof_pool.isBofValid(bof_handle));
}

fn run(
    bof_handle: BofHandle,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    out_context: **@import("bofapi").bof.Context,
) !void {
    const context = try gstate.allocator.?.create(BofContext);
    context.* = BofContext.init(gstate.allocator.?, bof_handle);
    errdefer {
        context.deinit();
        gstate.allocator.?.destroy(context);
    }

    if (gstate.bof_pool.getBofPtrIfValid(bof_handle)) |bof| {
        bof.run(
            context,
            if (arg_data_ptr) |ptr| ptr[0..@as(usize, @intCast(arg_data_len))] else null,
        );
        out_context.* = @ptrCast(context);
    } else unreachable;
}

pub export fn bofObjectRun(
    bof_handle: BofHandle,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    out_context: **@import("bofapi").bof.Context,
) callconv(.C) c_int {
    if (!gstate.is_valid) return -1;
    if (!gstate.bof_pool.isBofValid(bof_handle)) return 0; // ignore (no error)
    run(bof_handle, arg_data_ptr, arg_data_len, out_context) catch return -1;
    return 0; // success
}

fn bofThread(
    bof: *Bof,
    arg_data: ?[]u8,
    completion_cb: ?@import("bofapi").bof.CompletionCallback,
    completion_cb_context: ?*anyopaque,
    context: *BofContext,
) void {
    bof.run(context, arg_data);

    if (arg_data) |ad| gstate.allocator.?.free(ad);
    if (completion_cb) |cb| {
        cb(@ptrCast(context), completion_cb_context);
    }
}

fn bofThreadCloneProc(
    bof: *Bof,
    arg_data: ?[]u8,
    completion_cb: ?@import("bofapi").bof.CompletionCallback,
    completion_cb_context: ?*anyopaque,
    context: *BofContext,
) void {
    if (@import("builtin").os.tag == .windows) { // and @import("builtin").cpu.arch == .x86_64) {
        var info: w32.RTL_USER_PROCESS_INFORMATION = undefined;
        const status = w32.RtlCloneUserProcess(
            w32.RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES,
            null,
            null,
            null,
            &info,
        );
        switch (status) {
            .PROCESS_CLONED => {
                // child process
                bof.run(context, arg_data);
            },
            .SUCCESS => {
                // parent process
                const wait_status = w32.WaitForSingleObject(info.ProcessHandle.?, w32.INFINITE);
                print("Wait status: {d}\n", .{wait_status});
                print("Status (parent): {d}\n", .{status});

                // TODO: Get output and result from the child process
                context.result = 0;
                context.done_event.set();
            },
            else => {
                print("Failed to clone the process ({d})\n", .{status});
                context.result = 0xff; // error
                context.done_event.set();
            },
        }

        if (arg_data) |ad| gstate.allocator.?.free(ad);
        if (completion_cb) |cb| {
            cb(@ptrCast(context), completion_cb_context);
        }
    } else {
        bofThread(bof, arg_data, completion_cb, completion_cb_context, context);
    }
}

const BofContext = struct {
    const max_output_len = 16 * 1024;

    allocator: std.mem.Allocator,

    done_event: std.Thread.ResetEvent = .{},
    handle: BofHandle,
    result: u8 = 0xff, // TODO: Make atomic

    output: std.ArrayList(u8),
    output_ring: std.RingBuffer,
    output_ring_num_written_bytes: usize = 0,
    output_mutex: std.Thread.Mutex = .{},

    fn init(allocator: std.mem.Allocator, handle: BofHandle) BofContext {
        return .{
            .allocator = allocator,
            .handle = handle,
            .output_ring = std.RingBuffer.init(allocator, max_output_len) catch @panic("OOM"),
            .output = std.ArrayList(u8).initCapacity(allocator, max_output_len + 1) catch @panic("OOM"),
        };
    }

    fn deinit(context: *BofContext) void {
        context.output_ring.deinit(context.allocator);
        context.output.deinit();
        context.* = undefined;
    }
};

fn runAsync(
    bof_handle: BofHandle,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    completion_cb: ?@import("bofapi").bof.CompletionCallback,
    completion_cb_context: ?*anyopaque,
    comptime run_in_new_process: bool,
    out_context: **@import("bofapi").bof.Context,
) !void {
    const context = try gstate.allocator.?.create(BofContext);
    context.* = BofContext.init(gstate.allocator.?, bof_handle);
    errdefer {
        context.deinit();
        gstate.allocator.?.destroy(context);
    }

    const arg_data = if (arg_data_ptr) |ptr| blk: {
        const data = try gstate.allocator.?.alloc(u8, @intCast(arg_data_len));
        @memcpy(data, ptr[0..@intCast(arg_data_len)]);
        break :blk data;
    } else null;
    errdefer {
        if (arg_data) |ad| gstate.allocator.?.free(ad);
    }

    if (gstate.bof_pool.getBofPtrIfValid(bof_handle)) |bof| {
        const thread = try std.Thread.spawn(
            .{},
            if (run_in_new_process) bofThreadCloneProc else bofThread,
            .{ bof, arg_data, completion_cb, completion_cb_context, context },
        );
        out_context.* = @ptrCast(context);
        thread.detach();
    } else unreachable;
}

pub export fn bofObjectRunAsync(
    bof_handle: BofHandle,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    completion_cb: ?@import("bofapi").bof.CompletionCallback,
    completion_cb_context: ?*anyopaque,
    out_context: **@import("bofapi").bof.Context,
) callconv(.C) c_int {
    if (!gstate.is_valid) return -1;
    if (!gstate.bof_pool.isBofValid(bof_handle)) return 0; // ignore (no error)
    runAsync(
        bof_handle,
        arg_data_ptr,
        arg_data_len,
        completion_cb,
        completion_cb_context,
        false,
        out_context,
    ) catch return -1;
    return 0; // success
}

pub export fn bofObjectRunAsyncProc(
    bof_handle: BofHandle,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    completion_cb: ?@import("bofapi").bof.CompletionCallback,
    completion_cb_context: ?*anyopaque,
    out_context: **@import("bofapi").bof.Context,
) callconv(.C) c_int {
    if (!gstate.is_valid) return -1;
    if (!gstate.bof_pool.isBofValid(bof_handle)) return 0; // ignore (no error)
    runAsync(
        bof_handle,
        arg_data_ptr,
        arg_data_len,
        completion_cb,
        completion_cb_context,
        true, // run in new process
        out_context,
    ) catch return -1;
    return 0; // success
}

pub export fn bofContextRelease(context: *@import("bofapi").bof.Context) void {
    if (!gstate.is_valid) return;
    const ctx = @as(*BofContext, @ptrCast(@alignCast(context)));
    ctx.deinit();
    gstate.allocator.?.destroy(ctx);
}

pub export fn bofContextIsRunning(context: *@import("bofapi").bof.Context) c_int {
    if (!gstate.is_valid) return 0;
    const ctx = @as(*BofContext, @ptrCast(@alignCast(context)));
    return @intFromBool(ctx.done_event.isSet() == false);
}

pub export fn bofContextGetObjectHandle(context: *@import("bofapi").bof.Context) BofHandle {
    if (!gstate.is_valid) return .{};
    const ctx = @as(*BofContext, @ptrCast(@alignCast(context)));
    return ctx.handle;
}

pub export fn bofContextGetReturnedValue(context: *@import("bofapi").bof.Context) u8 {
    if (!gstate.is_valid) return 0;
    const ctx = @as(*BofContext, @ptrCast(@alignCast(context)));
    return ctx.result;
}

pub export fn bofContextWait(context: *@import("bofapi").bof.Context) void {
    if (!gstate.is_valid) return;
    const ctx = @as(*BofContext, @ptrCast(@alignCast(context)));
    ctx.done_event.wait();
}

pub export fn bofContextGetOutput(context: *BofContext, len: ?*c_int) callconv(.C) ?[*:0]const u8 {
    if (!gstate.is_valid) return null;

    context.output_mutex.lock();
    defer context.output_mutex.unlock();

    const output_len = @min(context.output_ring_num_written_bytes, BofContext.max_output_len);
    if (len != null) len.?.* = @intCast(output_len);
    if (output_len == 0) return null;

    const slice = context.output_ring.sliceLast(output_len);

    context.output.clearRetainingCapacity();
    context.output.appendSliceAssumeCapacity(slice.first);
    context.output.appendSliceAssumeCapacity(slice.second);

    context.output.items.len += 1;
    context.output.items[output_len] = 0;

    return @ptrCast(context.output.items.ptr);
}

const page_size = 4096;
const max_section_size = 8 * page_size;
const max_num_external_functions = 256;

const w32 = @import("bofapi").win32;

const thunk_offset = switch (@import("builtin").cpu.arch) {
    .x86_64 => 2,
    .x86 => 1,
    .aarch64 => 8,
    .arm => 8,
    else => unreachable,
};
// zig fmt: off
const thunk_trampoline = switch (@import("builtin").cpu.arch) {
    .x86_64 => [_]u8{
        0x48, 0xb8, // mov rax, imm64
        undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,
        0xff, 0xe0, // jmp rax
    },
    .x86 => [_]u8{
        0xb8, // mov eax, imm32
        undefined, undefined, undefined, undefined,
        0xff, 0xe0, // jmp eax
    },
    .aarch64 => [_]u8{
        0x50, 0x00, 0x00, 0x58, // ldr x16, #8
        0x00, 0x02, 0x1f, 0xd6, // br x16
        undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,
    },
    .arm => [_]u8{
        0x00, 0xc0, 0x9f, 0xe5, // ldr r12, [pc] ; pc points two instructions ahead
        0x1c, 0xff, 0x2f, 0xe1, // bx r12
        undefined, undefined, undefined, undefined,
    },
    else => unreachable,
};
// zig fmt: on

const coff = struct {
    const Reloc = extern struct {
        virtual_address: u32 align(1),
        symbol_table_index: u32 align(1),
        type: u16 align(1),
    };
    comptime {
        assert(@sizeOf(Reloc) == 10);
    }

    // Reloc `type`:
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-relocations-object-only
    const IMAGE_REL_AMD64_ADDR64 = 1;
    const IMAGE_REL_AMD64_ADDR32NB = 3;
    const IMAGE_REL_AMD64_REL32 = 4;

    const IMAGE_REL_I386_DIR32 = 6;
    const IMAGE_REL_I386_REL32 = 20;
};

const R_AARCH64_CALL26 = 283;
const R_AARCH64_ADR_PREL_PG_HI21 = 275;
const R_AARCH64_ADD_ABS_LO12_NC = 277;
const R_AARCH64_JUMP26 = 282;
const R_AARCH64_LDST8_ABS_LO12_NC = 278;
const R_AARCH64_LDST16_ABS_LO12_NC = 284;
const R_AARCH64_LDST32_ABS_LO12_NC = 285;
const R_AARCH64_LDST64_ABS_LO12_NC = 286;
const R_AARCH64_LDST128_ABS_LO12_NC = 299;
const R_AARCH64_ABS64 = 257;
const R_AARCH64_PREL32 = 261;

const R_ARM_ABS32 = 2;
const R_ARM_REL32 = 3;
const R_ARM_CALL = 28;
const R_ARM_JUMP24 = 29;
const R_ARM_NONE = 0;
const R_ARM_PREL31 = 42;

extern fn __ashlti3(a: i128, b: i32) callconv(.C) i128;
extern fn __ashldi3(a: i64, b: i32) callconv(.C) i64;
extern fn __udivdi3(a: u64, b: u64) callconv(.C) u64;
extern fn __divti3(a: i128, b: i128) callconv(.C) i128;
extern fn __divdi3(a: i64, b: i64) callconv(.C) i64;
extern fn __modti3(a: i128, b: i128) callconv(.C) i128;
extern fn __aeabi_llsl(a: i64, b: i32) callconv(.AAPCS) i64;
extern fn __aeabi_uidiv(n: u32, d: u32) callconv(.AAPCS) u32;
extern fn __aeabi_uldivmod() callconv(.Naked) void;
extern fn __aeabi_ldivmod() callconv(.Naked) void;
extern fn memset(dest: ?[*]u8, c: u8, len: usize) callconv(.C) ?[*]u8;
extern fn memcpy(noalias dest: ?[*]u8, noalias src: ?[*]const u8, len: usize) callconv(.C) ?[*]u8;

export fn allocateMemory(size: usize) callconv(.C) ?*anyopaque {
    gstate.mutex.lock();
    defer gstate.mutex.unlock();

    const mem = gstate.allocator.?.alignedAlloc(
        u8,
        mem_alignment,
        size,
    ) catch @panic("out of memory");

    gstate.allocations.?.put(@intFromPtr(mem.ptr), size) catch @panic("out of memory");

    return mem.ptr;
}

export fn freeMemory(maybe_ptr: ?*anyopaque) callconv(.C) void {
    if (maybe_ptr) |ptr| {
        gstate.mutex.lock();
        defer gstate.mutex.unlock();

        const size = gstate.allocations.?.fetchRemove(@intFromPtr(ptr)).?.value;
        const mem = @as([*]align(mem_alignment) u8, @ptrCast(@alignCast(ptr)))[0..size];
        gstate.allocator.?.free(mem);
    }
}

export fn allocateAndZeroMemory(num: usize, size: usize) callconv(.C) ?*anyopaque {
    const ptr = allocateMemory(num * size);
    if (ptr != null) {
        @memset(@as([*]u8, @ptrCast(ptr))[0 .. num * size], 0);
        return ptr;
    }
    return null;
}

export fn outputBofData(_: i32, data: [*]u8, len: i32, free_mem: i32) void {
    var context = gstate.current_bof_context.?;

    context.output_mutex.lock();
    defer context.output_mutex.unlock();

    const slice = data[0..@intCast(len)];

    context.output_ring.writeSliceAssumeCapacity(slice);
    context.output_ring_num_written_bytes += slice.len;

    if (free_mem != 0) {
        freeMemory(data);
    }
}

export fn getEnviron() callconv(.C) [*:null]?[*:0]const u8 {
    // TODO: Implement this properly (std.os.environ is not a good solution)
    const static = struct {
        var environ: [1:null]?[*:0]const u8 = .{"todo"};
    };
    return &static.environ;
}

const mem_alignment = 16;

const gstate = struct {
    var is_valid: bool = false;
    var gpa: ?std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 0 }) = null;
    var allocator: ?std.mem.Allocator = null;
    var allocations: ?std.AutoHashMap(usize, usize) = null;
    var mutex: std.Thread.Mutex = .{};
    var func_lookup: std.StringHashMap(usize) = undefined;

    threadlocal var current_bof_context: ?*BofContext = null;
    var bof_pool: BofPool = undefined;
};

fn initLauncher() !void {
    gstate.mutex.lock();
    defer gstate.mutex.unlock();

    if (gstate.is_valid)
        return; // Already initialized

    gstate.gpa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 0 }){};
    errdefer {
        _ = gstate.gpa.?.deinit();
        gstate.gpa = null;
    }

    gstate.allocator = gstate.gpa.?.allocator();
    errdefer gstate.allocator = null;

    gstate.allocations = std.AutoHashMap(usize, usize).init(gstate.allocator.?);
    errdefer {
        gstate.allocations.?.deinit();
        gstate.allocations = null;
    }

    gstate.func_lookup = std.StringHashMap(usize).init(gstate.allocator.?);
    errdefer {
        gstate.func_lookup.deinit();
        gstate.func_lookup = undefined;
    }

    const impl = @import("beacon/beacon_impl.zig");
    const is32w = @import("builtin").cpu.arch == .x86 and @import("builtin").os.tag == .windows;

    try gstate.func_lookup.put(if (is32w) "_BeaconPrintf" else "BeaconPrintf", @intFromPtr(&impl.BeaconPrintf));
    try gstate.func_lookup.put(if (is32w) "_BeaconOutput" else "BeaconOutput", @intFromPtr(&impl.BeaconOutput));
    try gstate.func_lookup.put(
        if (is32w) "_BeaconDataParse" else "BeaconDataParse",
        @intFromPtr(&impl.BeaconDataParse),
    );
    try gstate.func_lookup.put(if (is32w) "_BeaconDataInt" else "BeaconDataInt", @intFromPtr(&impl.BeaconDataInt));
    try gstate.func_lookup.put(
        if (is32w) "_BeaconDataShort" else "BeaconDataShort",
        @intFromPtr(&impl.BeaconDataShort),
    );
    try gstate.func_lookup.put(
        if (is32w) "_BeaconDataUSize" else "BeaconDataUSize",
        @intFromPtr(&impl.BeaconDataUSize),
    );
    try gstate.func_lookup.put(
        if (is32w) "_BeaconDataExtract" else "BeaconDataExtract",
        @intFromPtr(&impl.BeaconDataExtract),
    );
    try gstate.func_lookup.put(
        if (is32w) "_BeaconDataLength" else "BeaconDataLength",
        @intFromPtr(&impl.BeaconDataLength),
    );
    try gstate.func_lookup.put(
        if (is32w) "_BeaconFormatAlloc" else "BeaconFormatAlloc",
        @intFromPtr(&impl.BeaconFormatAlloc),
    );
    try gstate.func_lookup.put(
        if (is32w) "_BeaconFormatReset" else "BeaconFormatReset",
        @intFromPtr(&impl.BeaconFormatReset),
    );
    try gstate.func_lookup.put(
        if (is32w) "_BeaconFormatFree" else "BeaconFormatFree",
        @intFromPtr(&impl.BeaconFormatFree),
    );
    try gstate.func_lookup.put(
        if (is32w) "_BeaconFormatAppend" else "BeaconFormatAppend",
        @intFromPtr(&impl.BeaconFormatAppend),
    );
    try gstate.func_lookup.put(
        if (is32w) "_BeaconFormatPrintf" else "BeaconFormatPrintf",
        @intFromPtr(&impl.BeaconFormatPrintf),
    );
    try gstate.func_lookup.put(
        if (is32w) "_BeaconFormatToString" else "BeaconFormatToString",
        @intFromPtr(&impl.BeaconFormatToString),
    );
    try gstate.func_lookup.put(
        if (is32w) "_BeaconFormatInt" else "BeaconFormatInt",
        @intFromPtr(&impl.BeaconFormatInt),
    );
    try gstate.func_lookup.put(if (is32w) "_getOSName" else "getOSName", @intFromPtr(&impl.getOSName));
    try gstate.func_lookup.put(if (is32w) "_getEnviron" else "getEnviron", @intFromPtr(&impl.getEnviron));
    try gstate.func_lookup.put(if (is32w) "_memset" else "memset", @intFromPtr(&memset));
    try gstate.func_lookup.put(if (is32w) "_memcpy" else "memcpy", @intFromPtr(&memcpy));
    try gstate.func_lookup.put(if (is32w) "_calloc" else "calloc", @intFromPtr(&allocateAndZeroMemory));
    try gstate.func_lookup.put(if (is32w) "_free" else "free", @intFromPtr(&freeMemory));
    try gstate.func_lookup.put(if (is32w) "___ashlti3" else "__ashlti3", @intFromPtr(&__ashlti3));
    if (@import("builtin").cpu.arch != .arm) {
        try gstate.func_lookup.put(if (is32w) "___ashldi3" else "__ashldi3", @intFromPtr(&__ashldi3));
    }
    try gstate.func_lookup.put(if (is32w) "___udivdi3" else "__udivdi3", @intFromPtr(&__udivdi3));
    try gstate.func_lookup.put(if (is32w) "___divti3" else "__divti3", @intFromPtr(&__divti3));
    try gstate.func_lookup.put(if (is32w) "___divdi3" else "__divdi3", @intFromPtr(&__divdi3));
    try gstate.func_lookup.put(if (is32w) "___modti3" else "__modti3", @intFromPtr(&__modti3));

    //TODO: should be loaded dynamically with std.DynLib.open
    if (@import("builtin").os.tag == .linux) {
        const libc = @import("bofapi").unix;

        try gstate.func_lookup.put("puts", @intFromPtr(&libc.puts));
        try gstate.func_lookup.put("printf", @intFromPtr(&libc.printf));

        // https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/time.h.html
        try gstate.func_lookup.put("ctime", @intFromPtr(&libc.ctime));

        // https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/utmpx.h.html
        try gstate.func_lookup.put("setutxent", @intFromPtr(&libc.setutxent));
        try gstate.func_lookup.put("getutxent", @intFromPtr(&libc.getutxent));
        try gstate.func_lookup.put("getutxid", @intFromPtr(&libc.getutxid));
        try gstate.func_lookup.put("endutxent", @intFromPtr(&libc.endutxent));
    }

    if (@import("builtin").os.tag == .windows) {
        switch (@import("builtin").cpu.arch) {
            .x86_64 => {
                try gstate.func_lookup.put("WriteFile", @intFromPtr(&w32.WriteFile));
                try gstate.func_lookup.put("GetLastError", @intFromPtr(&w32.GetLastError));
                try gstate.func_lookup.put("ExitProcess", @intFromPtr(&w32.ExitProcess));
                try gstate.func_lookup.put("VirtualAlloc", @intFromPtr(&w32.VirtualAlloc));
                try gstate.func_lookup.put("VirtualFree", @intFromPtr(&w32.VirtualFree));
                try gstate.func_lookup.put("LoadLibraryA", @intFromPtr(&w32.LoadLibraryA));
                try gstate.func_lookup.put("GetModuleHandleA", @intFromPtr(&w32.GetModuleHandleA));
                try gstate.func_lookup.put("GetProcAddress", @intFromPtr(&w32.GetProcAddress));
            },
            .x86 => {
                try gstate.func_lookup.put("_WriteFile@20", @intFromPtr(&w32.WriteFile));
                try gstate.func_lookup.put("_GetLastError@0", @intFromPtr(&w32.GetLastError));
                try gstate.func_lookup.put("_ExitProcess@4", @intFromPtr(&w32.ExitProcess));
                try gstate.func_lookup.put("_VirtualAlloc@16", @intFromPtr(&w32.VirtualAlloc));
                try gstate.func_lookup.put("_VirtualFree@12", @intFromPtr(&w32.VirtualFree));
                try gstate.func_lookup.put("_LoadLibraryA@4", @intFromPtr(&w32.LoadLibraryA));
                try gstate.func_lookup.put("_GetModuleHandleA@4", @intFromPtr(&w32.GetModuleHandleA));
                try gstate.func_lookup.put("_GetProcAddress@8", @intFromPtr(&w32.GetProcAddress));
            },
            else => unreachable,
        }
    }

    if (@import("builtin").cpu.arch == .arm) {
        // TODO: Add more.
        try gstate.func_lookup.put("__aeabi_llsl", @intFromPtr(&__aeabi_llsl));
        try gstate.func_lookup.put("__aeabi_uidiv", @intFromPtr(&__aeabi_uidiv));
        try gstate.func_lookup.put("__aeabi_uldivmod", @intFromPtr(&__aeabi_uldivmod));
        try gstate.func_lookup.put("__aeabi_ldivmod", @intFromPtr(&__aeabi_ldivmod));
    }

    gstate.bof_pool = BofPool.init(gstate.allocator.?);

    gstate.is_valid = true;
}

pub export fn bofLauncherInit() callconv(.C) c_int {
    initLauncher() catch return -1;
    return 0;
}

pub export fn bofLauncherRelease() callconv(.C) void {
    gstate.mutex.lock();
    defer gstate.mutex.unlock();

    if (!gstate.is_valid) return;

    gstate.is_valid = false;

    gstate.bof_pool.deinit(gstate.allocator.?);

    gstate.func_lookup.deinit();
    gstate.func_lookup = undefined;

    assert(gstate.allocations.?.count() == 0);

    gstate.allocations.?.deinit();
    gstate.allocations = null;

    gstate.allocator = null;

    assert(gstate.gpa.?.deinit() == .ok);
    gstate.gpa = null;
}
