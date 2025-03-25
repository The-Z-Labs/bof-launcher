const std = @import("std");
const assert = std.debug.assert;

const pubapi = @import("bof_launcher_api.zig");

pub const std_options = .{
    .log_level = std.log.default_level,
};

const BofHandle = packed struct(u32) {
    index: u16 = 0,
    generation: u16 = 0,
};
comptime {
    assert(@sizeOf(BofHandle) == @sizeOf(pubapi.Object));
    assert(@alignOf(BofHandle) == @alignOf(pubapi.Object));
}

const BofSection = struct {
    mem: []u8,
    is_code: bool,
};

const Bof = struct {
    const max_num_sections = 16;

    is_allocated: bool = false,
    is_loaded: bool = false,

    sections_mem: ?[]u8 = null,
    sections: [max_num_sections]BofSection = undefined,
    sections_num: u32 = 0,

    entry_point: ?*const fn (arg_data: ?[*]u8, arg_len: i32) callconv(.C) u8 = null,

    user_externals: std.StringHashMap(usize) = undefined,

    masking_enabled: bool = true,
    is_masked: bool = false,

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

        std.log.debug("Trying to run go()...", .{});

        const tid = getCurrentThreadId();

        std.log.debug("Thread id = {d}", .{tid});

        var maybe_prev_context: ?*BofContext = null;

        {
            gstate.mutex.lock();
            defer gstate.mutex.unlock();

            maybe_prev_context = if (gstate.bof_contexts.get(getCurrentThreadId())) |ctx| ctx else null;

            gstate.bof_contexts.put(tid, context) catch @panic("OOM");
        }
        std.log.debug("Entering go()...", .{});
        const exit_code = bof.entry_point.?(
            if (arg_data) |ad| ad.ptr else null,
            if (arg_data) |ad| @as(i32, @intCast(ad.len)) else 0,
        );
        _ = context.exit_code.swap(exit_code, .seq_cst);
        {
            gstate.mutex.lock();
            defer gstate.mutex.unlock();
            gstate.bof_contexts.put(tid, maybe_prev_context) catch @panic("OOM");
        }

        std.log.debug("Returned '{d}' from go().", .{exit_code});
    }

    const obj_file_data_alignment = 512;

    fn load(bof: *Bof, allocator: std.mem.Allocator, file_data: []const u8) !void {
        assert(bof.is_allocated == true);

        bof.unload();
        errdefer {
            bof.unload();
            bof.is_allocated = false;
        }

        bof.user_externals = std.StringHashMap(usize).init(allocator);

        bof.is_loaded = true;

        const aligned_file_data = try allocator.alignedAlloc(u8, obj_file_data_alignment, file_data.len);
        defer allocator.free(aligned_file_data);

        @memcpy(aligned_file_data, file_data);

        if (@import("builtin").os.tag == .linux) {
            try bof.loadElf(allocator, aligned_file_data);
        } else {
            try bof.loadCoff(allocator, aligned_file_data);
        }
    }

    fn unload(bof: *Bof) void {
        if (bof.is_loaded) {
            assert(bof.is_allocated == true);

            if (bof.sections_mem) |slice| {
                if (@import("builtin").os.tag == .windows) {
                    _ = w32.VirtualFree(slice.ptr, 0, w32.MEM_RELEASE);
                } else if (@import("builtin").os.tag == .linux) {
                    _ = linux.munmap(slice.ptr, slice.len);
                }
            }

            {
                var it = bof.user_externals.iterator();
                while (it.next()) |kv| {
                    bof.user_externals.allocator.free(kv.key_ptr.*);
                }
            }
            bof.user_externals.deinit();

            bof.masking_enabled = true;
            bof.is_masked = false;
            bof.sections_mem = null;
            bof.entry_point = null;
            bof.is_loaded = false;
        }
    }

    fn loadCoff(
        bof: *Bof,
        allocator: std.mem.Allocator,
        file_data: []align(obj_file_data_alignment) const u8,
    ) !void {
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
        std.log.debug("COFF HEADER:", .{});
        std.log.debug("{any}\n\n", .{header});

        var section_mappings = std.ArrayList([]u8).init(arena);
        defer section_mappings.deinit();

        const section_headers = parser.getSectionHeaders();

        const max_section_size = gstate.page_size * 8;

        const all_sections_mem = blk: {
            const size = (section_headers.len + 1) * max_section_size;
            const addr = w32.VirtualAlloc(
                null,
                size,
                w32.MEM_COMMIT | w32.MEM_RESERVE | w32.MEM_TOP_DOWN,
                w32.PAGE_READWRITE,
            );
            if (addr == null) return error.VirtualAllocFailed;
            break :blk @as([*]u8, @ptrCast(addr))[0..size];
        };
        bof.sections_mem = all_sections_mem;

        const got_base_addr = @intFromPtr(all_sections_mem.ptr);

        var func_addr_to_got_entry = std.AutoHashMap(usize, u32).init(arena);
        defer func_addr_to_got_entry.deinit();

        assert((section_headers.len + 1) <= max_num_sections);

        // Start from 1 because 0 is reserved for GOT section.
        bof.sections_num = 1;

        var section_offset: usize = max_section_size;
        for (section_headers) |section_header| {
            const section_name = parser.getSectionName(&section_header);
            std.log.debug("SECTION NAME: {!s}", .{section_name});
            std.log.debug("{any}\n\n", .{section_header});

            if (section_header.size_of_raw_data > 0) {
                const section_data = all_sections_mem[section_offset .. section_offset +
                    section_header.size_of_raw_data];

                @memcpy(
                    section_data,
                    file_data[section_header.pointer_to_raw_data..][0..section_header.size_of_raw_data],
                );

                try section_mappings.append(@alignCast(section_data));

                section_offset += max_section_size;

                bof.sections[bof.sections_num] = .{
                    .mem = section_data,
                    .is_code = section_header.isCode(),
                };
                bof.sections_num += 1;
            } else {
                try section_mappings.append(@as([*]u8, undefined)[0..0]);
            }
        }

        const symtab = parser.getSymtab().?;
        const strtab = (try parser.getStrtab()).?;

        for (section_headers, 0..) |section_header, section_index| {
            const section_name = parser.getSectionName(&section_header);
            std.log.debug("SECTION NAME: {!s} ({d})", .{ section_name, section_index });

            const relocs = @as(
                [*]align(1) const coff.Reloc,
                @ptrCast(file_data[section_header.pointer_to_relocations..]),
            )[0..section_header.number_of_relocations];

            for (relocs) |reloc| {
                const sym = symtab.at(reloc.symbol_table_index, .symbol);
                const sym_name, const declspec_dllimport = sym_info: {
                    const p_sym_name = p_sym_name: {
                        if (sym.symbol.getName()) |name| {
                            break :p_sym_name name;
                        } else if (sym.symbol.getNameOffset()) |offset| {
                            break :p_sym_name strtab.get(offset);
                        } else {
                            unreachable;
                        }
                    };
                    const prefix = "__imp_";
                    if (p_sym_name.len > prefix.len and std.mem.eql(u8, prefix, p_sym_name[0..prefix.len])) {
                        break :sym_info .{ p_sym_name[prefix.len..], true };
                    }
                    break :sym_info .{ p_sym_name, false };
                };

                std.log.debug("SYMBOL NAME: {s}", .{sym_name});
                std.log.debug("__declspec(dllimport): {}", .{declspec_dllimport});
                std.log.debug("{any}", .{reloc});
                std.log.debug("{any}", .{sym.symbol});

                var maybe_func_addr = gstate.func_lookup.get(sym_name);

                if (@import("builtin").cpu.arch == .x86) {
                    if (maybe_func_addr == null and
                        @intFromEnum(sym.symbol.section_number) == 0 and
                        std.mem.indexOfScalar(u8, sym_name, '@') != null)
                    {
                        var it = std.mem.split(u8, sym_name, "@");
                        const func_name = it.first();
                        maybe_func_addr = gstate.func_lookup.get(func_name[1..]);
                    }
                }

                if (maybe_func_addr == null and
                    @intFromEnum(sym.symbol.section_number) == 0 and
                    std.mem.indexOfScalar(u8, sym_name, '$') != null)
                {
                    var it = std.mem.split(u8, sym_name, "$");
                    const dll_name = it.first();

                    assert(!std.mem.eql(u8, dll_name, sym_name));

                    std.log.debug("Parsing LibName$FuncName symbol:", .{});

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

                    std.log.debug("LibName is: {s}", .{dll_name_z});
                    std.log.debug("FuncName is: {s}", .{func_name_z});

                    maybe_func_addr = gstate.func_lookup.get(func_name_z);

                    if (maybe_func_addr == null) {
                        const dll = if (w32.GetModuleHandleA(dll_name_z)) |hmod|
                            hmod
                        else
                            w32.LoadLibraryA(dll_name_z).?;

                        maybe_func_addr = if (w32.GetProcAddress(dll, func_name_z)) |addr|
                            @intFromPtr(addr)
                        else
                            null;
                    }
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
                            "ntdll.dll",
                            "kernel32.dll",
                            "ole32.dll",
                            "user32.dll",
                            "secur32.dll",
                            "advapi32.dll",
                            "ws2_32.dll",
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
                    std.log.err("SYMBOL NAME: {s} NOT FOUND!", .{sym_name});
                    return error.UnknownFunction;
                }

                const addr_p = @intFromPtr(section_mappings.items[section_index].ptr) + reloc.virtual_address;
                const addr_s = if (@intFromEnum(sym.symbol.section_number) > 0)
                    @intFromPtr(section_mappings.items[@intFromEnum(sym.symbol.section_number) - 1].ptr)
                else
                    undefined;

                const addend = @as(*align(1) i32, @ptrFromInt(addr_p)).* + @as(i32, @intCast(sym.symbol.value));

                if (maybe_func_addr != null) {
                    const func_addr = maybe_func_addr.?;

                    const got_entry = if (func_addr_to_got_entry.get(func_addr)) |entry| entry else blk: {
                        const entry = func_addr_to_got_entry.count();
                        if (entry >= max_num_external_functions) {
                            std.log.err("Too many external functions used. Consider increasing `max_num_external_functions` constant.", .{});
                            return error.TooManyExternalFunctions;
                        }

                        try func_addr_to_got_entry.put(func_addr, entry);
                        break :blk entry;
                    };

                    const func_map_addr = got_base_addr + got_entry * thunk_trampoline.len;

                    if (declspec_dllimport) {
                        // We need to copy just an address
                        @memcpy(
                            @as([*]u8, @ptrFromInt(func_map_addr))[0..@sizeOf(usize)],
                            std.mem.asBytes(&func_addr),
                        );

                        if (@import("builtin").cpu.arch == .x86_64) {
                            // IMAGE_REL_AMD64_REL32
                            const addr: i32 = @intCast(
                                @as(isize, @intCast(func_map_addr)) - @as(isize, @intCast(addr_p)) - 4,
                            );

                            @as(*align(1) i32, @ptrFromInt(addr_p)).* = addr;
                        } else if (@import("builtin").cpu.arch == .x86) {
                            // IMAGE_REL_I386_DIR32
                            const addr: i32 = @intCast(
                                @as(isize, @intCast(func_map_addr)),
                            );

                            @as(*align(1) i32, @ptrFromInt(addr_p)).* = addr;
                        }
                    } else {
                        // We need to copy entire trampoline
                        var trampoline = [_]u8{0} ** thunk_trampoline.len;
                        @memcpy(trampoline[0..], thunk_trampoline[0..]);
                        @memcpy(trampoline[thunk_offset..][0..@sizeOf(usize)], std.mem.asBytes(&func_addr));
                        @memcpy(
                            @as([*]u8, @ptrFromInt(func_map_addr))[0..thunk_trampoline.len],
                            trampoline[0..],
                        );

                        // IMAGE_REL_AMD64_REL32 (x86_64) / IMAGE_REL_I386_REL32 (x86)
                        const addr: i32 = @intCast(
                            @as(isize, @intCast(func_map_addr)) - @as(isize, @intCast(addr_p)) - 4,
                        );

                        @as(*align(1) i32, @ptrFromInt(addr_p)).* = addr;
                    }
                } else if (@import("builtin").cpu.arch == .x86_64) {
                    switch (reloc.type) {
                        coff.IMAGE_REL_AMD64_ADDR64 => {
                            const a = @as(*align(1) i64, @ptrFromInt(addr_p)).* + sym.symbol.value;

                            const addr = @as(i64, @intCast(addr_s)) + a;

                            @as(*align(1) u64, @ptrFromInt(addr_p)).* = @bitCast(addr);
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
                        else => {
                            std.log.debug("Unhandled x86_64 COFF relocation ({d})", .{reloc.type});
                        },
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
                        else => {
                            std.log.debug("Unhandled x86 COFF relocation ({d})", .{reloc.type});
                        },
                    }
                }
                std.log.debug("", .{});
            }
        }

        // Section 0 is always GOT.
        bof.sections[0] = .{
            .mem = all_sections_mem[0 .. thunk_trampoline.len * func_addr_to_got_entry.count()],
            .is_code = true,
        };

        for (bof.sections[0..bof.sections_num]) |section| {
            if (section.is_code) {
                var old_protection: w32.DWORD = 0;
                if (w32.VirtualProtect(
                    section.mem.ptr,
                    section.mem.len,
                    w32.PAGE_EXECUTE_READ,
                    &old_protection,
                ) == w32.FALSE) return error.VirtualProtectFailed;

                _ = w32.FlushInstructionCache(w32.GetCurrentProcess(), section.mem.ptr, section.mem.len);
            }
        }

        var go: ?*const fn (arg_data: ?[*]u8, arg_len: i32) callconv(.C) u8 = null;
        for (0..header.number_of_symbols) |symbol_index| {
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
                std.log.debug("go() section index: {d}", .{section_index});

                const section = section_mappings.items[section_index];
                go = @as(
                    @TypeOf(go),
                    @ptrFromInt(@intFromPtr(section.ptr) + sym.symbol.value),
                );
            }

            if (@intFromEnum(sym.symbol.section_number) != 0 and sym.symbol.storage_class == .EXTERNAL) {
                // TODO: We support only functions for now
                if (sym.symbol.type.complex_type != .FUNCTION) continue;

                const section_index = @intFromEnum(sym.symbol.section_number) - 1;
                const section = section_mappings.items[section_index];
                const addr = @intFromPtr(section.ptr) + sym.symbol.value;

                const key = try allocator.dupe(u8, if (@import("builtin").cpu.arch == .x86) sym_name[1..] else sym_name);

                try bof.user_externals.put(key, addr);
            }
        }

        if (go) |_| {
            std.log.debug("go() FOUND.", .{});
        } else {
            std.log.debug("go() NOT FOUND.", .{});
        }

        bof.entry_point = go;
    }

    fn loadElf(
        bof: *Bof,
        allocator: std.mem.Allocator,
        file_data: []align(obj_file_data_alignment) const u8,
    ) !void {
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var section_headers = std.ArrayList(std.elf.Elf64_Shdr).init(arena);
        defer section_headers.deinit();

        var section_mappings = std.ArrayList([]u8).init(arena);
        defer section_mappings.deinit();

        var symbol_table: []const std.elf.Sym = undefined;
        var string_table: []const u8 = undefined;

        var file_data_stream = std.io.fixedBufferStream(file_data);

        const elf_hdr = try std.elf.Header.read(&file_data_stream);
        std.log.debug("Number of Sections: {d}", .{elf_hdr.shnum});

        // Load all section headers.
        {
            var section_headers_iter = elf_hdr.section_header_iterator(&file_data_stream);
            while (try section_headers_iter.next()) |section| {
                try section_headers.append(section);
            }
        }

        const max_section_size = gstate.page_size * 8;

        const all_sections_mem = blk: {
            const size = (section_headers.items.len + 1) * max_section_size;
            const addr = linux.mmap(
                null,
                size,
                linux.PROT.READ | linux.PROT.WRITE,
                .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
                -1,
                0,
            );
            if (addr == std.math.maxInt(usize)) return error.MMapFailed;
            break :blk @as([*]u8, @ptrFromInt(addr))[0..size];
        };
        bof.sections_mem = all_sections_mem;

        const got = all_sections_mem[0 .. max_num_external_functions * thunk_trampoline.len];

        var func_addr_to_got_entry = std.AutoHashMap(usize, u32).init(arena);
        defer func_addr_to_got_entry.deinit();

        assert((section_headers.items.len + 1) <= max_num_sections);

        // Start from 1 because 0 is reserved for GOT section.
        bof.sections_num = 1;

        var map_offset: usize = max_section_size;
        for (section_headers.items, 0..) |section, section_index| {
            std.log.debug("Section Index: {d}", .{section_index});
            std.log.debug("\tName is {d}", .{section.sh_name});
            std.log.debug("\tFlags are 0x{x}", .{section.sh_flags});
            std.log.debug("\tType is 0x{x}", .{section.sh_type});
            std.log.debug("\tSize is {d}", .{section.sh_size});
            std.log.debug("\tEntSize is {d}", .{section.sh_entsize});
            std.log.debug("\tOffset is 0x{x}", .{section.sh_offset});
            std.log.debug("\tAddr is 0x{x}", .{section.sh_addr});
            std.log.debug("\tLink is {d}", .{section.sh_link});
            std.log.debug("\tInfo is {d}", .{section.sh_info});

            const section_offset = @as(usize, @intCast(section.sh_offset));
            const section_size = @as(usize, @intCast(section.sh_size));

            if ((section.sh_type == std.elf.SHT_PROGBITS or
                section.sh_type == std.elf.SHT_NOBITS or
                section.sh_type == (std.elf.SHT_PROGBITS | std.elf.SHT_LOPROC)) and section.sh_size > 0)
            {
                const img = all_sections_mem[map_offset .. map_offset + section_size];

                try section_mappings.append(@alignCast(img));

                @memcpy(img, file_data[section_offset..][0..section_size]);

                map_offset += max_section_size;

                bof.sections[bof.sections_num] = .{
                    .mem = img,
                    .is_code = if ((section.sh_flags & std.elf.SHF_EXECINSTR) != 0) true else false,
                };
                bof.sections_num += 1;
            } else {
                try section_mappings.append(@as([*]u8, undefined)[0..0]);
            }

            switch (section.sh_type) {
                std.elf.SHT_STRTAB => {
                    const section_string_table = file_data[section_offset..][0..section_size];
                    std.log.debug("\t\tString Table: {s}", .{section_string_table});
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

                    std.log.debug("\t\tSymbol Table", .{});
                    std.log.debug("\t\tString Table: {s}", .{string_table});
                },
                else => {
                    std.log.debug("\t\tCase Not Handled", .{});
                },
            }
        }

        const sht_rel_type = if (@sizeOf(usize) == 8) std.elf.SHT_RELA else std.elf.SHT_REL;
        const ElfRel = if (@sizeOf(usize) == 8) std.elf.Rela else std.elf.Rel;

        for (section_headers.items, 0..) |section, section_index| {
            const section_offset = @as(usize, @intCast(section.sh_offset));
            const section_size = @as(usize, @intCast(section.sh_size));

            if (section.sh_type == std.elf.SHT_RELA) {
                std.log.debug("\tSection type: SHT_RELA", .{});
            } else if (section.sh_type == std.elf.SHT_REL) {
                std.log.debug("\tSection type: SHT_REL", .{});
            }

            if (section.sh_type == sht_rel_type) {
                std.log.debug("\tENTRIES (Section Index: {d})", .{section_index});

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
                    std.log.debug("\t\tSymbol: {s}", .{reloc_str});
                    std.log.debug("\t\tReloc type: {d}", .{reloc.r_type()});
                    std.log.debug("\t\tSymbol Value: 0x{x}", .{symbol.st_value});
                    std.log.debug("\t\tShndx: 0x{x}", .{symbol.st_shndx});
                    std.log.debug("\t\tInfo: 0x{x}", .{reloc.r_info});
                    std.log.debug("\t\tOffset: 0x{x}", .{reloc.r_offset});
                    std.log.debug("\t\tAddend: 0x{x}", .{addend});
                    std.log.debug("\t\taddr_p: 0x{x}", .{addr_p});
                    std.log.debug("\t\taddr_s: 0x{x}", .{addr_s});

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
                        var maybe_func_ptr = gstate.func_lookup.get(func_name);

                        if (maybe_func_ptr) |func_ptr| {
                            std.log.debug("\t\tNot defined in the obj: {s} 0x{x}", .{ func_name, func_ptr });
                        } else {
                            const func_name_z = try std.mem.concatWithSentinel(arena, u8, &.{func_name[0..]}, 0);
                            defer arena.free(func_name_z);

                            if (gstate.libc == null) {
                                gstate.libc = std.DynLib.open("libc.so.6") catch null;
                            }
                            if (gstate.libc != null) {
                                maybe_func_ptr = @intFromPtr(gstate.libc.?.lookup(*anyopaque, func_name_z));
                            }
                            if (maybe_func_ptr == null) {
                                std.log.err("\t\tFailed to find function {s}", .{func_name});
                                return error.UnknownFunction;
                            }
                        }
                        const func_ptr = maybe_func_ptr.?;

                        const got_entry = if (func_addr_to_got_entry.get(func_ptr)) |entry| entry else blk: {
                            const entry = func_addr_to_got_entry.count();
                            if (entry >= max_num_external_functions) {
                                std.log.err("Too many external functions used. Consider increasing `max_num_external_functions` constant.", .{});
                                return error.TooManyExternalFunctions;
                            }

                            try func_addr_to_got_entry.put(func_ptr, entry);
                            break :blk entry;
                        };

                        const a1 = @intFromPtr(got.ptr) + got_entry * thunk_trampoline.len;

                        var trampoline = [_]u8{0} ** thunk_trampoline.len;
                        @memcpy(trampoline[0..], thunk_trampoline[0..]);
                        @memcpy(trampoline[thunk_offset..][0..@sizeOf(usize)], std.mem.asBytes(&func_ptr));
                        @memcpy(@as([*]u8, @ptrFromInt(a1))[0..thunk_trampoline.len], trampoline[0..]);

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
                            R_AARCH64_CALL26, R_AARCH64_JUMP26 => {
                                const relative_offset = (@as(
                                    i32,
                                    @intCast(@as(i64, @intCast(addr_s)) + addend - @as(i64, @intCast(addr_p))),
                                ) & 0x0fff_ffff) >> 2;

                                // 0x94000000 BL (branch linked)
                                // 0x14000000 B (branch)
                                @as(*align(1) u32, @ptrFromInt(addr_p)).* =
                                    @as(u32, if (reloc.r_type() == R_AARCH64_CALL26) 0x94000000 else 0x14000000) |
                                    @as(u32, @bitCast(relative_offset));
                            },
                            R_AARCH64_ABS64 => {
                                const relative_offset = @as(i64, @intCast(addr_s)) + addend;

                                @as(*align(1) i64, @ptrFromInt(addr_p)).* = relative_offset;
                            },
                            R_AARCH64_ABS32 => {
                                const relative_offset = @as(i32, @intCast(addr_s)) + @as(i32, @intCast(addend));

                                @as(*align(1) i32, @ptrFromInt(addr_p)).* = relative_offset;
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
                            else => {
                                std.log.debug("Unhandled AARCH64 ELF relocation ({d})", .{reloc.r_type()});
                            },
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
                            else => {
                                std.log.debug("Unhandled ARM ELF relocation ({d})", .{reloc.r_type()});
                            },
                        }
                    } else if ((section.sh_flags & std.elf.SHF_INFO_LINK) != 0 and
                        @import("builtin").cpu.arch == .x86_64)
                    {
                        // RELOCATIONS FOR X86_64
                        // https://intezer.com/blog/malware-analysis/executable-and-linkable-format-101-part-3-relocations

                        switch (reloc.r_type()) {
                            0x1 => {
                                // R_X86_64_64, S + A
                                @as(*align(1) usize, @ptrFromInt(addr_p)).* =
                                    @as(usize, @intCast(@as(u64, @bitCast(@as(i64, @intCast(addr_s)) + addend))));
                            },
                            0x2, 0x4 => {
                                // R_X86_64_PC32 (0x2), S + A - P
                                // R_X86_64_PLT32 (0x4), L + A - P
                                const relative_offset: i32 =
                                    @intCast(@as(i64, @intCast(addr_s)) + addend - @as(i64, @intCast(addr_p)));

                                @as(*align(1) i32, @ptrFromInt(addr_p)).* = relative_offset;
                            },
                            else => {
                                std.log.debug("Unhandled x86_64 ELF relocation ({d})", .{reloc.r_type()});
                            },
                        }
                    } else if ((section.sh_flags & std.elf.SHF_INFO_LINK) != 0 and
                        @import("builtin").cpu.arch == .x86)
                    {
                        // RELOCATIONS FOR X86
                        // https://intezer.com/blog/malware-analysis/executable-and-linkable-format-101-part-3-relocations

                        switch (reloc.r_type()) {
                            0x1 => {
                                // R_386_32, S + A
                                @as(*align(1) usize, @ptrFromInt(addr_p)).* =
                                    @as(usize, @intCast(@as(u64, @bitCast(@as(i64, @intCast(addr_s)) + addend))));
                            },
                            0x2, 0x4 => {
                                // R_386_PC32 (0x2), S + A - P
                                // R_386_PLT32 (0x4), L + A - P
                                const relative_offset: i32 =
                                    @intCast(@as(i64, @intCast(addr_s)) + addend - @as(i64, @intCast(addr_p)));

                                @as(*align(1) i32, @ptrFromInt(addr_p)).* = relative_offset;
                            },
                            0x9 => {
                                // S + A - GOT
                                const relative_offset: i32 = @intCast(
                                    @as(i64, @intCast(addr_s)) + addend - @as(i64, @intCast(@intFromPtr(got.ptr))),
                                );

                                @as(*align(1) i32, @ptrFromInt(addr_p)).* = relative_offset;
                            },
                            else => {
                                std.log.debug("Unhandled x86 ELF relocation ({d})", .{reloc.r_type()});
                            },
                        }
                    }
                    std.log.debug("\t\t-------------------------------------------------", .{});
                }
            }
        }

        // Section 0 is always GOT.
        bof.sections[0] = .{
            .mem = all_sections_mem[0 .. thunk_trampoline.len * func_addr_to_got_entry.count()],
            .is_code = true,
        };

        for (bof.sections[0..bof.sections_num]) |section| {
            if (section.is_code) {
                const ret = linux.mprotect(
                    section.mem.ptr,
                    section.mem.len,
                    linux.PROT.READ | linux.PROT.EXEC,
                );
                if (ret == std.math.maxInt(usize)) return error.MProtectFailed;
            }
        }

        // Print all symbols; get pointer to `go()`.
        std.log.debug("SYMBOLS", .{});
        var go: ?*const fn (arg_data: ?[*]u8, arg_len: i32) callconv(.C) u8 = null;
        for (symbol_table) |sym| {
            if (sym.st_shndx != 0 and sym.st_shndx < section_headers.items.len) {
                const name = @as([*:0]const u8, @ptrCast(&string_table[sym.st_name]));
                std.log.debug(
                    "\tName: {s: <50} Address(real): 0x{x}",
                    .{ name, @intFromPtr(section_mappings.items[sym.st_shndx].ptr) + sym.st_value },
                );
                if (std.mem.len(name) == 2 and name[0] == 'g' and name[1] == 'o' and name[2] == 0) {
                    const section = section_mappings.items[sym.st_shndx].ptr[0..max_section_size];

                    go = @as(@TypeOf(go), @ptrFromInt(@intFromPtr(section.ptr) + sym.st_value));
                }
            }

            if (sym.st_shndx != 0 and sym.st_shndx < section_headers.items.len) {
                // TODO: We support only functions for now
                //const OK_TYPES = (1 << std.elf.STT_NOTYPE | 1 << std.elf.STT_OBJECT | 1 << std.elf.STT_FUNC | 1 << std.elf.STT_COMMON);

                const ok_types = (1 << std.elf.STT_FUNC);
                const ok_binds = (1 << std.elf.STB_GLOBAL | 1 << std.elf.STB_WEAK | 1 << std.elf.STB_GNU_UNIQUE);

                if (0 == (@as(u32, 1) << @as(u5, @intCast(sym.st_info & 0xf)) & ok_types)) continue;
                if (0 == (@as(u32, 1) << @as(u5, @intCast(sym.st_info >> 4)) & ok_binds)) continue;

                const section = section_mappings.items[sym.st_shndx].ptr[0..max_section_size];
                const addr = @intFromPtr(section.ptr) + sym.st_value;

                const sym_name = @as([*:0]const u8, @ptrCast(&string_table[sym.st_name]));
                const key = try allocator.dupe(u8, std.mem.span(sym_name));

                try bof.user_externals.put(key, addr);
            }
        }
        if (go) |_| {
            std.log.debug("go() FOUND.", .{});
        } else {
            std.log.debug("go() NOT FOUND.", .{});
        }

        bof.entry_point = go;
    }
};

const BofPool = struct {
    const max_num_bofs = 1024;

    bofs: []Bof,
    generations: []u16,

    fn init(allocator: std.mem.Allocator) BofPool {
        return .{
            .bofs = blk: {
                const bofs = allocator.alloc(Bof, max_num_bofs + 1) catch @panic("OOM");
                for (bofs) |*bof| bof.* = Bof.init();
                break :blk bofs;
            },
            .generations = blk: {
                const generations = allocator.alloc(u16, max_num_bofs + 1) catch @panic("OOM");
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

export fn bofArgsInit(out_args: **pubapi.Args) callconv(.C) c_int {
    const args = gstate.allocator.?.create(BofArgs) catch return -1;
    args.* = .{};
    out_args.* = @ptrCast(args);
    return 0;
}

export fn bofArgsRelease(args: *pubapi.Args) callconv(.C) void {
    const bof_args = @as(*BofArgs, @ptrCast(@alignCast(args)));
    if (bof_args.blob) |b| gstate.allocator.?.free(b[0..BofArgs.blob_size]);
    gstate.allocator.?.destroy(bof_args);
}

export fn bofArgsBegin(args: *pubapi.Args) callconv(.C) void {
    const bof_args = @as(*BofArgs, @ptrCast(@alignCast(args)));
    if (bof_args.blob) |b| gstate.allocator.?.free(b[0..BofArgs.blob_size]);
    bof_args.* = .{};
}

export fn bofArgsEnd(args: *pubapi.Args) callconv(.C) void {
    const bof_args = @as(*BofArgs, @ptrCast(@alignCast(args)));
    if (bof_args.blob != null) {
        bof_args.size = bof_args.size - bof_args.length;
        const len = bof_args.size - 4;
        @memcpy(bof_args.original.?[0..4], std.mem.asBytes(&len));
    }
}

export fn bofArgsGetBuffer(args: *pubapi.Args) callconv(.C) ?[*]u8 {
    const bof_args = @as(*BofArgs, @ptrCast(@alignCast(args)));
    return bof_args.original;
}

export fn bofArgsGetBufferSize(args: *pubapi.Args) callconv(.C) c_int {
    const bof_args = @as(*BofArgs, @ptrCast(@alignCast(args)));
    return bof_args.size;
}

export fn bofArgsAdd(args: *pubapi.Args, arg: [*]const u8, arg_size: c_int) callconv(.C) c_int {
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
        std.log.debug("Str param: {s} {d}", .{ sArg, sArg.len });

        const arg_len_w0 = arg_len + 1;
        @memcpy(params.buffer.?[0..4], std.mem.asBytes(&arg_len_w0));
        params.length -= 4;
        params.buffer.? += 4;

        @memcpy(params.buffer.?[0..@intCast(arg_len)], sArg);
        params.length -= arg_len;
        params.buffer.? += @as(usize, @intCast(arg_len));

        params.buffer.?[0] = 0;
        params.length -= 1;
        params.buffer.? += @as(usize, @intCast(1));
    } else if (std.mem.eql(u8, sArg_type, "int") or std.mem.eql(u8, sArg_type, "i")) {
        const numArg = std.fmt.parseUnsigned(u32, sArg, 10) catch return -1;

        std.log.debug("Int param: {s} {d}", .{ sArg, sArg.len });

        if (arg_len > params.length)
            return -1;

        @memcpy(params.buffer.?[0..4], std.mem.asBytes(&numArg));
        params.length -= 4;
        params.buffer.? += 4;
    } else if (std.mem.eql(u8, sArg_type, "short") or std.mem.eql(u8, sArg_type, "s")) {
        const numArg = std.fmt.parseUnsigned(u16, sArg, 10) catch return -1;

        std.log.debug("Short param: {s} {d}", .{ sArg, sArg.len });

        if (arg_len > params.length)
            return -1;

        @memcpy(params.buffer.?[0..2], std.mem.asBytes(&numArg));
        params.length -= 2;
        params.buffer.? += 2;
    }
    // TODO: add wstr (wide chars) support

    return 0;
}

export fn bofObjectInitFromMemory(
    file_data_ptr: [*]const u8,
    file_data_len: c_int,
    out_bof_handle: ?*BofHandle,
) callconv(.C) c_int {
    if (out_bof_handle == null) return -1;

    const res = bofLauncherInit();
    if (res < 0) return res;

    const bof_handle = gstate.bof_pool.allocateBofHandle();
    var bof = gstate.bof_pool.getBofPtrIfValid(bof_handle).?;

    bof.load(gstate.allocator.?, file_data_ptr[0..@as(usize, @intCast(file_data_len))]) catch {
        std.log.debug("Failed to load BOF. Aborting.", .{});
        return -1;
    };

    out_bof_handle.?.* = bof_handle;
    return 0;
}

export fn bofRun(
    file_data_ptr: [*]const u8,
    file_data_len: c_int,
) callconv(.C) c_int {
    var bof_handle: BofHandle = undefined;
    const init_res = bofObjectInitFromMemory(file_data_ptr, file_data_len, &bof_handle);
    if (init_res < 0) return init_res;

    var bof_context: *pubapi.Context = undefined;
    const run_res = bofObjectRun(bof_handle, null, 0, &bof_context);
    if (run_res < 0) {
        bofObjectRelease(bof_handle);
        return run_res;
    }

    // TODO: For testing.
    if (false) {
        if (@import("builtin").os.tag == .windows) {
            if (init_res == 0 and run_res == 0) {
                const ctx = @as(*BofContext, @ptrCast(@alignCast(bof_context)));

                const user32_dll = w32.LoadLibraryA("user32.dll").?;
                const messageBox: *const fn (?*anyopaque, ?[*:0]const u8, ?[*:0]const u8, u32) callconv(w32.WINAPI) c_int =
                    @ptrCast(w32.GetProcAddress(user32_dll, "MessageBoxA"));

                _ = messageBox(null, bofContextGetOutput(ctx, null), "bbbbbbbbbbbb", 0);
            }
        }
    }

    const bof_exit_code = bofContextGetExitCode(bof_context);

    bofContextRelease(bof_context);
    bofObjectRelease(bof_handle);

    return bof_exit_code;
}

export fn bofObjectRelease(bof_handle: BofHandle) callconv(.C) void {
    if (!gstate.is_valid) return;

    gstate.bof_pool.unloadBofAndDeallocateHandle(bof_handle);
}

export fn bofObjectIsValid(bof_handle: BofHandle) callconv(.C) c_int {
    if (!gstate.is_valid) return 0;

    return @intFromBool(gstate.bof_pool.isBofValid(bof_handle));
}

export fn bofObjectGetProcAddress(bof_handle: BofHandle, name: ?[*:0]const u8) callconv(.C) ?*anyopaque {
    if (!gstate.is_valid) return null;
    if (name == null) return null;

    if (gstate.bof_pool.getBofPtrIfValid(bof_handle)) |bof| {
        if (bof.user_externals.get(std.mem.span(name.?))) |addr| return @ptrFromInt(addr);
        return null;
    }

    return null;
}

fn run(
    bof_handle: BofHandle,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    out_context: **pubapi.Context,
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
        context.done_event.set();
    } else unreachable;
}

fn runDebug(
    go_func: *const fn (?[*]u8, i32) callconv(.C) u8,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    out_context: **pubapi.Context,
) !void {
    const context = try gstate.allocator.?.create(BofContext);
    context.* = BofContext.init(gstate.allocator.?, .{});
    errdefer {
        context.deinit();
        gstate.allocator.?.destroy(context);
    }
    var bof = Bof{
        .is_allocated = true,
        .is_loaded = true,
        .entry_point = go_func,
    };
    bof.run(
        context,
        if (arg_data_ptr) |ptr| ptr[0..@as(usize, @intCast(arg_data_len))] else null,
    );
    out_context.* = @ptrCast(context);
    context.done_event.set();
}

export fn bofObjectRun(
    bof_handle: BofHandle,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    out_context: **pubapi.Context,
) callconv(.C) c_int {
    if (!gstate.is_valid) return -1;
    if (!gstate.bof_pool.isBofValid(bof_handle)) return 0; // ignore (no error)
    run(bof_handle, arg_data_ptr, arg_data_len, out_context) catch return -1;
    return 0; // success
}

export fn bofDebugRun(
    go_func: *const fn (?[*]u8, i32) callconv(.C) u8,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    out_context: **pubapi.Context,
) callconv(.C) c_int {
    const res = bofLauncherInit();
    if (res < 0) return res;
    runDebug(go_func, arg_data_ptr, arg_data_len, out_context) catch return -1;
    return 0; // success
}

const ThreadData = struct {
    bof: *Bof,
    arg_data: ?[]u8,
    completion_cb: ?pubapi.CompletionCallback,
    completion_cb_context: ?*anyopaque,
    context: *BofContext,
    run_in_new_process: bool,
};

fn threadFunc(raw_ptr: ?*anyopaque) callconv(.C) if (@import("builtin").os.tag == .windows)
    w32.DWORD
else
    ?*anyopaque {
    const in: *ThreadData = @ptrCast(@alignCast(raw_ptr));
    const context = in.context;

    if (in.run_in_new_process) {
        if (@import("builtin").os.tag == .windows)
            threadFuncCloneProcessWindows(in.bof, in.arg_data, context)
        else
            threadFuncCloneProcessLinux(in.bof, in.arg_data, context);
    } else {
        in.bof.run(context, in.arg_data);
    }

    if (in.completion_cb) |cb| {
        cb(@ptrCast(in.context), in.completion_cb_context);
    }
    if (in.arg_data) |ad| gstate.allocator.?.free(ad);
    gstate.allocator.?.destroy(in);

    context.done_event.set();

    return if (@import("builtin").os.tag == .windows) 0 else null;
}

fn threadFuncCloneProcessLinux(bof: *Bof, arg_data: ?[]u8, context: *BofContext) void {
    const pipe = std.posix.pipe() catch @panic("pipe() failed");
    defer {
        std.posix.close(pipe[0]);
        std.posix.close(pipe[1]);
    }

    const pid = std.posix.fork() catch @panic("fork() failed");
    if (pid == 0) {
        // child process
        bof.run(context, arg_data);

        const file = std.fs.File{ .handle = pipe[1] };
        file.writer().writeByte(context.exit_code.load(.seq_cst)) catch @panic("OOM");

        var output_len: i32 = undefined;
        const maybe_buf = bofContextGetOutput(context, &output_len);

        file.writer().writeInt(i32, output_len, .little) catch @panic("OOM");

        if (maybe_buf) |buf| {
            file.writer().writeAll(buf[0..@intCast(output_len)]) catch @panic("OOM");
        }

        std.posix.exit(0);
    }

    // parent process
    const child_result = std.posix.waitpid(pid, 0);
    if (child_result.status == 0) {
        const file = std.fs.File{ .handle = pipe[0] };
        const exit_code = file.reader().readByte() catch @panic("OOM");
        _ = context.exit_code.swap(exit_code, .seq_cst);

        const output_len = file.reader().readInt(u32, .little) catch @panic("OOM");

        if (output_len > 0) {
            context.output_mutex.lock();
            defer context.output_mutex.unlock();

            const read_len = file.reader().readAll(context.output_ring.data[0..output_len]) catch @panic("OOM");

            context.output_ring.read_index = 0;
            context.output_ring.write_index = read_len;
            context.output_ring_num_written_bytes = read_len;
        }
    } else {
        std.log.err("Child process crashed with status code 0x{x}\n", .{child_result.status});
        _ = context.exit_code.swap(0xff, .seq_cst); // error
    }
}

fn threadFuncCloneProcessWindows(bof: *Bof, arg_data: ?[]u8, context: *BofContext) void {
    var read_pipe: w32.HANDLE = undefined;
    var write_pipe: w32.HANDLE = undefined;
    var sec_attribs: w32.SECURITY_ATTRIBUTES = .{
        .nLength = @sizeOf(w32.SECURITY_ATTRIBUTES),
        .lpSecurityDescriptor = null,
        .bInheritHandle = w32.TRUE,
    };
    _ = w32.CreatePipe(&read_pipe, &write_pipe, &sec_attribs, BofContext.max_output_len + 16);
    defer {
        _ = w32.CloseHandle(read_pipe);
        _ = w32.CloseHandle(write_pipe);
    }

    var job_handle: w32.HANDLE = undefined;
    _ = w32.NtCreateJobObject(&job_handle, w32.JOB_OBJECT_ALL_ACCESS, null);
    defer _ = w32.NtClose(job_handle);

    var job_limits = std.mem.zeroes(w32.JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
    job_limits.BasicLimitInformation.LimitFlags =
        w32.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
        w32.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
        w32.JOB_OBJECT_LIMIT_BREAKAWAY_OK;

    _ = w32.NtSetInformationJobObject(
        job_handle,
        .JobObjectExtendedLimitInformation,
        &job_limits,
        @sizeOf(w32.JOBOBJECT_EXTENDED_LIMIT_INFORMATION),
    );

    var info: w32.RTL_USER_PROCESS_INFORMATION = undefined;
    info.Length = @sizeOf(w32.RTL_USER_PROCESS_INFORMATION);
    const status = w32.RtlCloneUserProcess(
        w32.RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES | w32.RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED,
        null,
        null,
        null,
        &info,
    );
    switch (status) {
        .PROCESS_CLONED => {
            // child process
            bof.run(context, arg_data);

            const exit_code = context.exit_code.load(.seq_cst);
            _ = w32.WriteFile(write_pipe, @ptrCast(&exit_code), 1, null, null);

            var output_len: i32 = undefined;
            const maybe_buf = bofContextGetOutput(context, &output_len);

            _ = w32.WriteFile(write_pipe, std.mem.asBytes(&output_len), 4, null, null);

            if (maybe_buf) |buf| {
                _ = w32.WriteFile(write_pipe, buf, @intCast(output_len), null, null);
            }

            _ = w32.NtTerminateProcess(w32.NtCurrentProcess(), .SUCCESS);
        },
        .SUCCESS => {
            // parent process
            _ = w32.NtAssignProcessToJobObject(job_handle, info.ProcessHandle.?);
            _ = w32.NtResumeThread(info.ThreadHandle.?, null);
            _ = w32.WaitForSingleObject(info.ProcessHandle.?, w32.INFINITE);

            var process_exit_code: w32.DWORD = 0xff;
            _ = w32.GetExitCodeProcess(info.ProcessHandle.?, &process_exit_code);

            if (process_exit_code == 0) {
                var exit_code: u8 = undefined;
                _ = w32.ReadFile(read_pipe, @ptrCast(&exit_code), 1, null, null);

                _ = context.exit_code.swap(exit_code, .seq_cst);

                var output_len: u32 = 0;
                _ = w32.ReadFile(read_pipe, std.mem.asBytes(&output_len), 4, null, null);

                if (output_len > 0) {
                    context.output_mutex.lock();
                    defer context.output_mutex.unlock();

                    var read_len: w32.DWORD = 0;
                    _ = w32.ReadFile(read_pipe, context.output_ring.data.ptr, output_len, &read_len, null);

                    context.output_ring.read_index = 0;
                    context.output_ring.write_index = read_len;
                    context.output_ring_num_written_bytes = read_len;
                }
            } else {
                std.log.err("Child process crashed with status code 0x{x}\n", .{process_exit_code});
                _ = context.exit_code.swap(0xff, .seq_cst); // error
            }
        },
        else => {
            std.log.err("Failed to clone the process ({d})\n", .{status});
            _ = context.exit_code.swap(0xff, .seq_cst); // error
        },
    }
}

const BofContext = struct {
    const max_output_len = 16 * 1024;

    allocator: std.mem.Allocator,

    done_event: std.Thread.ResetEvent = .{},
    handle: BofHandle,
    exit_code: std.atomic.Value(u8) = std.atomic.Value(u8).init(0xff),

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
    completion_cb: ?pubapi.CompletionCallback,
    completion_cb_context: ?*anyopaque,
    comptime run_in_new_process: bool,
    out_context: **pubapi.Context,
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
        const in = try gstate.allocator.?.create(ThreadData);

        // NOTE: We disable memory masking permanently for the BOF if it is launched in a dedicated thread.
        if (run_in_new_process == false) {
            bof.masking_enabled = false;
        }

        in.* = .{
            .bof = bof,
            .arg_data = arg_data,
            .completion_cb = completion_cb,
            .completion_cb_context = completion_cb_context,
            .context = context,
            .run_in_new_process = run_in_new_process,
        };
        if (@import("builtin").os.tag == .windows) {
            // TODO: Handle errors
            const handle = w32.CreateThread(null, 0, threadFunc, @ptrCast(in), 0, null);
            if (handle) |h| _ = w32.CloseHandle(h);
        } else {
            // TODO: Handle errors
            var handle: pthread_t = undefined;
            _ = gstate.pthread_create(&handle, null, threadFunc, @ptrCast(in));
            _ = gstate.pthread_detach(handle);
        }
        out_context.* = @ptrCast(context);
    } else unreachable;
}

export fn bofObjectRunAsyncThread(
    bof_handle: BofHandle,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    completion_cb: ?pubapi.CompletionCallback,
    completion_cb_context: ?*anyopaque,
    out_context: **pubapi.Context,
) callconv(.C) c_int {
    if (!gstate.is_valid) return -1;
    if (!gstate.bof_pool.isBofValid(bof_handle)) return 0; // ignore (no error)
    runAsync(
        bof_handle,
        arg_data_ptr,
        arg_data_len,
        completion_cb,
        completion_cb_context,
        false, // run in new process
        out_context,
    ) catch return -1;
    return 0; // success
}

export fn bofObjectRunAsyncProcess(
    bof_handle: BofHandle,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    completion_cb: ?pubapi.CompletionCallback,
    completion_cb_context: ?*anyopaque,
    out_context: **pubapi.Context,
) callconv(.C) c_int {
    if (@import("builtin").cpu.arch == .x86 and @import("builtin").os.tag == .windows) {
        var is_wow64: w32.BOOL = w32.FALSE;
        _ = w32.IsWow64Process(w32.GetCurrentProcess(), &is_wow64);
        if (is_wow64 == w32.TRUE)
            return -1; // TODO: Make it work (Windows bug?)
    }
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

export fn bofMemoryMaskKey(key: [*]const u8, key_len: c_int) callconv(.C) c_int {
    if (!gstate.is_valid) return -1;
    if (key_len > gstate.mask_key_data.len) return -1;
    for (0..@intCast(key_len)) |i| {
        gstate.mask_key_data[i] = key[i];
    }
    gstate.mask_key = gstate.mask_key_data[0..@intCast(key_len)];
    return 0;
}

export fn bofMemoryMaskWin32ApiCall(win32_api_name: [*:0]const u8, masking_enabled: c_int) callconv(.C) c_int {
    if (!gstate.is_valid) return -1;
    if (std.mem.eql(u8, std.mem.span(win32_api_name), "all")) {
        inline for (@typeInfo(ZGateWin32ApiCall).Enum.fields, 0..) |_, i| {
            gstate.mask_win32_api[i] = if (masking_enabled == 0) false else true;
        }
    } else {
        inline for (@typeInfo(ZGateWin32ApiCall).Enum.fields, 0..) |field, i| {
            if (std.mem.eql(u8, std.mem.span(win32_api_name), field.name)) {
                gstate.mask_win32_api[i] = if (masking_enabled == 0) false else true;
                return 0;
            }
        }
        return -1;
    }
    return 0;
}

export fn bofContextRelease(context: *pubapi.Context) callconv(.C) void {
    if (!gstate.is_valid) return;
    const ctx = @as(*BofContext, @ptrCast(@alignCast(context)));
    ctx.deinit();
    gstate.allocator.?.destroy(ctx);
}

export fn bofContextIsRunning(context: *pubapi.Context) callconv(.C) c_int {
    if (!gstate.is_valid) return 0;
    const ctx = @as(*BofContext, @ptrCast(@alignCast(context)));
    return @intFromBool(ctx.done_event.isSet() == false);
}

export fn bofContextGetObjectHandle(context: *pubapi.Context) callconv(.C) u32 {
    if (!gstate.is_valid) return 0;
    const ctx = @as(*BofContext, @ptrCast(@alignCast(context)));
    return @bitCast(ctx.handle);
}

export fn bofContextGetExitCode(context: *pubapi.Context) callconv(.C) u8 {
    if (!gstate.is_valid) return 0;
    const ctx = @as(*BofContext, @ptrCast(@alignCast(context)));
    return ctx.exit_code.load(.seq_cst);
}

export fn bofContextWait(context: *pubapi.Context) callconv(.C) void {
    if (!gstate.is_valid) return;
    const ctx = @as(*BofContext, @ptrCast(@alignCast(context)));
    ctx.done_event.wait();
}

export fn bofContextGetOutput(context: *BofContext, len: ?*c_int) callconv(.C) ?[*:0]const u8 {
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

const max_num_external_functions = 256;

const w32 = @import("win32.zig");
const linux = std.os.linux;

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
        0, 0, 0, 0, // padding to 16 bytes
    },
    .x86 => [_]u8{
        0xb8, // mov eax, imm32
        undefined, undefined, undefined, undefined,
        0xff, 0xe0, // jmp eax
        0, // padding to 8
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
const R_AARCH64_ABS32 = 258;
const R_AARCH64_PREL32 = 261;
const R_AARCH64_ADR_GOT_PAGE = 311;
const R_AARCH64_LD64_GOT_LO12_NC = 312;

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
extern fn ___chkstk_ms() callconv(.Naked) void;
extern fn __zig_probe_stack() callconv(.Naked) void;
extern fn _alloca() callconv(.Naked) void;

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

fn getCurrentThreadId() u32 {
    if (@import("builtin").os.tag == .windows) {
        return @intCast(w32.GetCurrentThreadId());
    }
    return @intCast(linux.gettid());
}

fn getCurrentProcessId() u32 {
    if (@import("builtin").os.tag == .windows) {
        return @intCast(w32.GetCurrentProcessId());
    }
    return @intCast(linux.getpid());
}

fn queryPageSize() u32 {
    if (@import("builtin").os.tag == .windows) {
        var info: w32.SYSTEM_INFO = undefined;
        w32.GetSystemInfo(&info);
        return @intCast(info.dwPageSize);
    }
    // TODO: Is it correct?
    const page_size: u32 = @intCast(linux.getauxval(std.elf.AT_PAGESZ));
    return if (page_size != 0) page_size else 4096;
}

export fn outputBofData(_: i32, data: [*]u8, len: i32, free_mem: i32) void {
    defer if (free_mem != 0) freeMemory(data);

    var context = context: {
        gstate.mutex.lock();
        defer gstate.mutex.unlock();

        const maybe_context = gstate.bof_contexts.get(getCurrentThreadId());

        // TODO: BeaconPrintf and friends called outside of bofObjectRun*() will print nothing.
        if (maybe_context == null) return;
        if (maybe_context.? == null) return;

        break :context maybe_context.?.?;
    };

    context.output_mutex.lock();
    defer context.output_mutex.unlock();

    const slice = data[0..@intCast(len)];

    context.output_ring.writeSliceAssumeCapacity(slice);
    context.output_ring_num_written_bytes += slice.len;
}

export fn getEnviron() callconv(.C) [*:null]?[*:0]const u8 {
    // TODO: Implement this properly
    const static = struct {
        var environ: [1:null]?[*:0]const u8 = .{"todo"};
    };
    return &static.environ;
}

const mem_alignment = 16;

pub fn panic(_: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    while (true) {
        @breakpoint();
    }
}

const pthread_t = *opaque {};

const gstate = struct {
    var is_valid: bool = false;
    var gpa: ?std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 0 }) = null;
    var allocator: ?std.mem.Allocator = null;
    var allocations: ?std.AutoHashMap(usize, usize) = null;
    var mutex: std.Thread.Mutex = .{};
    var func_lookup: std.StringHashMap(usize) = undefined;

    var libc: if (@import("builtin").os.tag == .linux) ?std.DynLib else void = null;
    var libpthread: if (@import("builtin").os.tag == .linux) ?std.DynLib else void = null;
    var pthread_create: *const fn (
        noalias newthread: *pthread_t,
        noalias attr: ?*anyopaque,
        start_routine: *const fn (?*anyopaque) callconv(.C) ?*anyopaque,
        noalias arg: ?*anyopaque,
    ) callconv(.C) c_int = undefined;
    var pthread_detach: *const fn (pthread_t) callconv(.C) c_int = undefined;

    var bof_contexts: std.AutoHashMap(u32, ?*BofContext) = undefined;
    var bof_pool: BofPool = undefined;

    var mask_key_data: [32]u8 = undefined;
    var mask_key: []const u8 = mask_key_data[0..13];
    var mask_win32_api: [@typeInfo(ZGateWin32ApiCall).Enum.fields.len]bool = undefined;

    var process_id: u32 = 0;
    var main_thread_id: u32 = 0;

    var page_size: u32 = 0;
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
    try gstate.func_lookup.put(if (is32w) "_malloc" else "malloc", @intFromPtr(&allocateMemory));
    try gstate.func_lookup.put(if (is32w) "_free" else "free", @intFromPtr(&freeMemory));
    try gstate.func_lookup.put(if (is32w) "___ashlti3" else "__ashlti3", @intFromPtr(&__ashlti3));
    if (@import("builtin").cpu.arch != .arm) {
        try gstate.func_lookup.put(if (is32w) "___ashldi3" else "__ashldi3", @intFromPtr(&__ashldi3));
    }
    try gstate.func_lookup.put(if (is32w) "___udivdi3" else "__udivdi3", @intFromPtr(&__udivdi3));
    try gstate.func_lookup.put(if (is32w) "___divti3" else "__divti3", @intFromPtr(&__divti3));
    try gstate.func_lookup.put(if (is32w) "___divdi3" else "__divdi3", @intFromPtr(&__divdi3));
    try gstate.func_lookup.put(if (is32w) "___modti3" else "__modti3", @intFromPtr(&__modti3));

    try gstate.func_lookup.put(if (is32w) "_bofRun" else "bofRun", @intFromPtr(&bofRun));
    try gstate.func_lookup.put(
        if (is32w) "_bofObjectInitFromMemory" else "bofObjectInitFromMemory",
        @intFromPtr(&bofObjectInitFromMemory),
    );
    try gstate.func_lookup.put(if (is32w) "_bofObjectRun" else "bofObjectRun", @intFromPtr(&bofObjectRun));
    try gstate.func_lookup.put(if (is32w) "_bofObjectRelease" else "bofObjectRelease", @intFromPtr(&bofObjectRelease));
    try gstate.func_lookup.put(if (is32w) "_bofObjectIsValid" else "bofObjectIsValid", @intFromPtr(&bofObjectIsValid));
    try gstate.func_lookup.put(
        if (is32w) "_bofObjectGetProcAddress" else "bofObjectGetProcAddress",
        @intFromPtr(&bofObjectGetProcAddress),
    );
    try gstate.func_lookup.put(
        if (is32w) "_bofObjectRunAsyncThread" else "bofObjectRunAsyncThread",
        @intFromPtr(&bofObjectRunAsyncThread),
    );
    try gstate.func_lookup.put(
        if (is32w) "_bofObjectRunAsyncProcess" else "bofObjectRunAsyncProcess",
        @intFromPtr(&bofObjectRunAsyncProcess),
    );
    try gstate.func_lookup.put(
        if (is32w) "_bofContextGetOutput" else "bofContextGetOutput",
        @intFromPtr(&bofContextGetOutput),
    );
    try gstate.func_lookup.put(if (is32w) "_bofContextRelease" else "bofContextRelease", @intFromPtr(&bofContextRelease));
    try gstate.func_lookup.put(
        if (is32w) "_bofContextIsRunning" else "bofContextIsRunning",
        @intFromPtr(&bofContextIsRunning),
    );
    try gstate.func_lookup.put(if (is32w) "_bofContextWait" else "bofContextWait", @intFromPtr(&bofContextWait));
    try gstate.func_lookup.put(
        if (is32w) "_bofContextGetExitCode" else "bofContextGetExitCode",
        @intFromPtr(&bofContextGetExitCode),
    );
    try gstate.func_lookup.put(
        if (is32w) "_bofContextGetObjectHandle" else "bofContextGetObjectHandle",
        @intFromPtr(&bofContextGetObjectHandle),
    );
    try gstate.func_lookup.put(if (is32w) "_bofArgsInit" else "bofArgsInit", @intFromPtr(&bofArgsInit));
    try gstate.func_lookup.put(if (is32w) "_bofArgsRelease" else "bofArgsRelease", @intFromPtr(&bofArgsRelease));
    try gstate.func_lookup.put(if (is32w) "_bofArgsAdd" else "bofArgsAdd", @intFromPtr(&bofArgsAdd));
    try gstate.func_lookup.put(if (is32w) "_bofArgsBegin" else "bofArgsBegin", @intFromPtr(&bofArgsBegin));
    try gstate.func_lookup.put(if (is32w) "_bofArgsEnd" else "bofArgsEnd", @intFromPtr(&bofArgsEnd));
    try gstate.func_lookup.put(if (is32w) "_bofArgsGetBuffer" else "bofArgsGetBuffer", @intFromPtr(&bofArgsGetBuffer));
    try gstate.func_lookup.put(
        if (is32w) "_bofArgsGetBufferSize" else "bofArgsGetBufferSize",
        @intFromPtr(&bofArgsGetBufferSize),
    );

    if (@import("builtin").os.tag == .windows) {
        try gstate.func_lookup.put("VirtualAlloc", @intFromPtr(&zgateVirtualAlloc));
        try gstate.func_lookup.put("VirtualAllocEx", @intFromPtr(&zgateVirtualAllocEx));
        try gstate.func_lookup.put("VirtualFree", @intFromPtr(&zgateVirtualFree));
        try gstate.func_lookup.put("VirtualQuery", @intFromPtr(&zgateVirtualQuery));
        try gstate.func_lookup.put("VirtualProtect", @intFromPtr(&zgateVirtualProtect));
        try gstate.func_lookup.put("VirtualProtectEx", @intFromPtr(&zgateVirtualProtectEx));
        try gstate.func_lookup.put("CreateFileMappingA", @intFromPtr(&zgateCreateFileMappingA));
        try gstate.func_lookup.put("CloseHandle", @intFromPtr(&zgateCloseHandle));
        try gstate.func_lookup.put("DuplicateHandle", @intFromPtr(&zgateDuplicateHandle));
        try gstate.func_lookup.put("GetThreadContext", @intFromPtr(&zgateGetThreadContext));
        try gstate.func_lookup.put("SetThreadContext", @intFromPtr(&zgateSetThreadContext));
        try gstate.func_lookup.put("MapViewOfFile", @intFromPtr(&zgateMapViewOfFile));
        try gstate.func_lookup.put("UnmapViewOfFile", @intFromPtr(&zgateUnmapViewOfFile));
        try gstate.func_lookup.put("OpenProcess", @intFromPtr(&zgateOpenProcess));
        try gstate.func_lookup.put("OpenThread", @intFromPtr(&zgateOpenThread));
        try gstate.func_lookup.put("WriteProcessMemory", @intFromPtr(&zgateWriteProcessMemory));
        try gstate.func_lookup.put("ReadProcessMemory", @intFromPtr(&zgateReadProcessMemory));
        try gstate.func_lookup.put("ResumeThread", @intFromPtr(&zgateResumeThread));
        try gstate.func_lookup.put("CreateThread", @intFromPtr(&zgateCreateThread));
        try gstate.func_lookup.put("CreateRemoteThread", @intFromPtr(&zgateCreateRemoteThread));

        try gstate.func_lookup.put("WriteFile", @intFromPtr(&w32.WriteFile));
        try gstate.func_lookup.put("GetLastError", @intFromPtr(&w32.GetLastError));
        try gstate.func_lookup.put("ExitProcess", @intFromPtr(&w32.ExitProcess));
        try gstate.func_lookup.put("LoadLibraryA", @intFromPtr(&w32.LoadLibraryA));
        try gstate.func_lookup.put("GetModuleHandleA", @intFromPtr(&w32.GetModuleHandleA));
        try gstate.func_lookup.put("GetProcAddress", @intFromPtr(&w32.GetProcAddress));
    }

    if (@import("builtin").cpu.arch == .arm) {
        // TODO: Add more.
        try gstate.func_lookup.put("__aeabi_llsl", @intFromPtr(&__aeabi_llsl));
        try gstate.func_lookup.put("__aeabi_uidiv", @intFromPtr(&__aeabi_uidiv));
        try gstate.func_lookup.put("__aeabi_uldivmod", @intFromPtr(&__aeabi_uldivmod));
        try gstate.func_lookup.put("__aeabi_ldivmod", @intFromPtr(&__aeabi_ldivmod));
    }

    gstate.bof_contexts = std.AutoHashMap(u32, ?*BofContext).init(gstate.allocator.?);
    gstate.bof_pool = BofPool.init(gstate.allocator.?);

    if (@import("builtin").os.tag == .windows) {
        // NOTE(mziulek):
        // Below code loads socket implementation and is required for RtlCloneUserProcess() to work correctly with sockets.
        var wsadata: w32.WSADATA = undefined;
        _ = w32.WSAStartup(0x0202, &wsadata);
        const sock = w32.WSASocketW(w32.AF.INET, w32.SOCK.DGRAM, 0, null, 0, 0);
        _ = w32.closesocket(sock);

        _ = w32.CoInitializeEx(null, w32.COINIT_MULTITHREADED);
    }

    if (@import("builtin").os.tag == .linux) {
        gstate.libpthread = try std.DynLib.open("libpthread.so.0");

        gstate.pthread_create = gstate.libpthread.?.lookup(@TypeOf(gstate.pthread_create), "pthread_create").?;
        gstate.pthread_detach = gstate.libpthread.?.lookup(@TypeOf(gstate.pthread_detach), "pthread_detach").?;
    }

    for (0..gstate.mask_key_data.len) |i| {
        gstate.mask_key_data[i] = @intCast((i + 7) % 255);
    }
    for (&gstate.mask_win32_api) |*enabled| enabled.* = true;

    gstate.process_id = getCurrentProcessId();
    gstate.main_thread_id = getCurrentThreadId();

    gstate.page_size = queryPageSize();

    gstate.is_valid = true;

    try pubapi.memoryMaskWin32ApiCall("all", true);
    try pubapi.memoryMaskWin32ApiCall("ResumeThread", false);
}

export fn bofLauncherInit() callconv(.C) c_int {
    initLauncher() catch return -1;
    return 0;
}

export fn bofLauncherRelease() callconv(.C) void {
    gstate.mutex.lock();
    defer gstate.mutex.unlock();

    if (!gstate.is_valid) return;

    gstate.is_valid = false;

    if (@import("builtin").os.tag == .windows) {
        w32.CoUninitialize();
        _ = w32.WSACleanup();
    }
    if (@import("builtin").os.tag == .linux) {
        if (gstate.libc != null) {
            gstate.libc.?.close();
            gstate.libc = null;
        }
        if (gstate.libpthread != null) {
            gstate.libpthread.?.close();
            gstate.libpthread = null;
        }
    }

    gstate.bof_pool.deinit(gstate.allocator.?);
    gstate.bof_contexts.deinit();

    gstate.func_lookup.deinit();
    gstate.func_lookup = undefined;

    assert(gstate.allocations.?.count() == 0);

    gstate.allocations.?.deinit();
    gstate.allocations = null;

    gstate.allocator = null;

    assert(gstate.gpa.?.deinit() == .ok);
    gstate.gpa = null;
}

const ZGateWin32ApiCall = enum(u32) {
    CreateRemoteThread = 0,
    CreateThread,
    GetThreadContext,
    MapViewOfFile,
    OpenProcess,
    OpenThread,
    ReadProcessMemory,
    ResumeThread,
    SetThreadContext,
    UnmapViewOfFile,
    WriteProcessMemory,
    VirtualAlloc,
    VirtualAllocEx,
    VirtualFree,
    VirtualProtect,
    VirtualProtectEx,
    VirtualQuery,
    CreateFileMappingA,
    CloseHandle,
    DuplicateHandle,
};

fn zgateMaskAllBofs() linksection(".zgate") void {
    for (gstate.bof_pool.bofs) |*bof| {
        if (bof.is_allocated and bof.is_loaded and !bof.is_masked and bof.masking_enabled) {
            for (bof.sections[0..bof.sections_num]) |section| {
                if (section.is_code) {
                    if (@import("builtin").os.tag == .windows) {
                        var old_protection: w32.DWORD = 0;
                        if (w32.VirtualProtect(
                            section.mem.ptr,
                            section.mem.len,
                            w32.PAGE_READWRITE,
                            &old_protection,
                        ) == w32.FALSE) return; // TODO: Handle error

                        _ = w32.FlushInstructionCache(w32.GetCurrentProcess(), section.mem.ptr, section.mem.len);
                    }
                }
            }

            for (bof.sections[0..bof.sections_num]) |section| {
                for (section.mem, 0..) |*byte, i| {
                    byte.* ^= gstate.mask_key[i % gstate.mask_key.len];
                }
            }

            bof.is_masked = true;
        }
    }
}

fn zgateUnmaskAllBofs() linksection(".zgate") void {
    for (gstate.bof_pool.bofs) |*bof| {
        if (bof.is_allocated and bof.is_loaded and bof.is_masked and bof.masking_enabled) {
            for (bof.sections[0..bof.sections_num]) |section| {
                for (section.mem, 0..) |*byte, i| {
                    byte.* ^= gstate.mask_key[i % gstate.mask_key.len];
                }
            }

            for (bof.sections[0..bof.sections_num]) |section| {
                if (section.is_code) {
                    if (@import("builtin").os.tag == .windows) {
                        var old_protection: w32.DWORD = 0;
                        if (w32.VirtualProtect(
                            section.mem.ptr,
                            section.mem.len,
                            w32.PAGE_EXECUTE_READ,
                            &old_protection,
                        ) == w32.FALSE) return; // TODO: Handle error

                        _ = w32.FlushInstructionCache(w32.GetCurrentProcess(), section.mem.ptr, section.mem.len);
                    }
                }
            }

            bof.is_masked = false;
        }
    }
}

fn zgateBegin(func: ZGateWin32ApiCall) linksection(".zgate") bool {
    if (getCurrentProcessId() == gstate.process_id and getCurrentThreadId() != gstate.main_thread_id) return false;
    if (!gstate.mask_win32_api[@intFromEnum(func)]) return false;
    zgateMaskAllBofs();
    if (false) std.debug.print("Mask: {s}\n", .{@tagName(func)});
    return true;
}

fn zgateEnd() linksection(".zgate") void {
    zgateUnmaskAllBofs();
}

fn zgateVirtualAlloc(
    lpAddress: ?w32.LPVOID,
    dwSize: w32.SIZE_T,
    flAllocationType: w32.DWORD,
    flProtect: w32.DWORD,
) linksection(".zgate") callconv(w32.WINAPI) ?w32.LPVOID {
    const do_mask = zgateBegin(.VirtualAlloc);
    const ret = w32.VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateVirtualAllocEx(
    hProcess: w32.HANDLE,
    lpAddress: ?w32.LPVOID,
    dwSize: w32.SIZE_T,
    flAllocationType: w32.DWORD,
    flProtect: w32.DWORD,
) linksection(".zgate") callconv(w32.WINAPI) ?w32.LPVOID {
    const do_mask = zgateBegin(.VirtualAllocEx);
    const ret = w32.VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateVirtualFree(
    lpAddress: ?w32.LPVOID,
    dwSize: w32.SIZE_T,
    dwFreeType: w32.DWORD,
) linksection(".zgate") callconv(w32.WINAPI) w32.BOOL {
    const do_mask = zgateBegin(.VirtualFree);
    const ret = w32.VirtualFree(lpAddress, dwSize, dwFreeType);
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateVirtualQuery(
    lpAddress: ?w32.LPVOID,
    lpBuffer: w32.PMEMORY_BASIC_INFORMATION,
    dwLength: w32.SIZE_T,
) linksection(".zgate") callconv(w32.WINAPI) w32.SIZE_T {
    const do_mask = zgateBegin(.VirtualQuery);
    const ret = w32.VirtualQuery(lpAddress, lpBuffer, dwLength);
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateVirtualProtect(
    lpAddress: w32.LPVOID,
    dwSize: w32.SIZE_T,
    flNewProtect: w32.DWORD,
    lpflOldProtect: *w32.DWORD,
) linksection(".zgate") callconv(w32.WINAPI) w32.BOOL {
    const do_mask = zgateBegin(.VirtualProtect);
    const ret = w32.VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateVirtualProtectEx(
    hProcess: w32.HANDLE,
    lpAddress: w32.LPVOID,
    dwSize: w32.SIZE_T,
    flNewProtect: w32.DWORD,
    lpflOldProtect: *w32.DWORD,
) linksection(".zgate") callconv(w32.WINAPI) w32.BOOL {
    const do_mask = zgateBegin(.VirtualProtectEx);
    const ret = w32.VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateCreateFileMappingA(
    hFile: w32.HANDLE,
    lpFileMappingAttributes: ?*w32.SECURITY_ATTRIBUTES,
    flProtect: w32.DWORD,
    dwMaximumSizeHigh: w32.DWORD,
    dwMaximumSizeLow: w32.DWORD,
    lpName: ?w32.LPCSTR,
) linksection(".zgate") callconv(w32.WINAPI) ?w32.HANDLE {
    const do_mask = zgateBegin(.CreateFileMappingA);
    const ret = w32.CreateFileMappingA(
        hFile,
        lpFileMappingAttributes,
        flProtect,
        dwMaximumSizeHigh,
        dwMaximumSizeLow,
        lpName,
    );
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateCloseHandle(hObject: w32.HANDLE) linksection(".zgate") callconv(w32.WINAPI) w32.BOOL {
    const do_mask = zgateBegin(.CloseHandle);
    const ret = w32.CloseHandle(hObject);
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateDuplicateHandle(
    hSourceProcessHandle: w32.HANDLE,
    hSourceHandle: w32.HANDLE,
    hTargetProcessHandle: w32.HANDLE,
    lpTargetHandle: *w32.HANDLE,
    dwDesiredAccess: w32.DWORD,
    bInheritHandle: w32.BOOL,
    dwOptions: w32.DWORD,
) linksection(".zgate") callconv(w32.WINAPI) w32.BOOL {
    const do_mask = zgateBegin(.DuplicateHandle);
    const ret = w32.DuplicateHandle(
        hSourceProcessHandle,
        hSourceHandle,
        hTargetProcessHandle,
        lpTargetHandle,
        dwDesiredAccess,
        bInheritHandle,
        dwOptions,
    );
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateGetThreadContext(
    hThread: w32.HANDLE,
    lpContext: *w32.CONTEXT,
) linksection(".zgate") callconv(w32.WINAPI) w32.BOOL {
    const do_mask = zgateBegin(.GetThreadContext);
    const ret = w32.GetThreadContext(hThread, lpContext);
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateSetThreadContext(
    hThread: w32.HANDLE,
    lpContext: *const w32.CONTEXT,
) linksection(".zgate") callconv(w32.WINAPI) w32.BOOL {
    const do_mask = zgateBegin(.SetThreadContext);
    const ret = w32.SetThreadContext(hThread, lpContext);
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateMapViewOfFile(
    hFileMappingObject: w32.HANDLE,
    dwDesiredAccess: w32.DWORD,
    dwFileOffsetHigh: w32.DWORD,
    dwFileOffsetLow: w32.DWORD,
    dwNumberOfBytesToMap: w32.SIZE_T,
) linksection(".zgate") callconv(w32.WINAPI) w32.LPVOID {
    const do_mask = zgateBegin(.MapViewOfFile);
    const ret = w32.MapViewOfFile(
        hFileMappingObject,
        dwDesiredAccess,
        dwFileOffsetHigh,
        dwFileOffsetLow,
        dwNumberOfBytesToMap,
    );
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateUnmapViewOfFile(lpBaseAddress: w32.LPCVOID) linksection(".zgate") callconv(w32.WINAPI) w32.BOOL {
    const do_mask = zgateBegin(.UnmapViewOfFile);
    const ret = w32.UnmapViewOfFile(lpBaseAddress);
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateOpenProcess(
    dwDesiredAccess: w32.DWORD,
    bInheritHandle: w32.BOOL,
    dwProcessId: w32.DWORD,
) linksection(".zgate") callconv(w32.WINAPI) w32.HANDLE {
    const do_mask = zgateBegin(.OpenProcess);
    const ret = w32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateOpenThread(
    dwDesiredAccess: w32.DWORD,
    bInheritHandle: w32.BOOL,
    dwThreadId: w32.DWORD,
) linksection(".zgate") callconv(w32.WINAPI) w32.HANDLE {
    const do_mask = zgateBegin(.OpenProcess);
    const ret = w32.OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateWriteProcessMemory(
    hProcess: w32.HANDLE,
    lpBaseAddress: w32.LPVOID,
    lpBuffer: w32.LPCVOID,
    nSize: w32.SIZE_T,
    lpNumberOfBytesWritten: ?*w32.SIZE_T,
) linksection(".zgate") callconv(w32.WINAPI) w32.BOOL {
    const do_mask = zgateBegin(.WriteProcessMemory);
    const ret = w32.WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateReadProcessMemory(
    hProcess: w32.HANDLE,
    lpBaseAddress: w32.LPCVOID,
    lpBuffer: w32.LPVOID,
    nSize: w32.SIZE_T,
    lpNumberOfBytesRead: ?*w32.SIZE_T,
) linksection(".zgate") callconv(w32.WINAPI) w32.BOOL {
    const do_mask = zgateBegin(.ReadProcessMemory);
    const ret = w32.ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateResumeThread(hThread: w32.HANDLE) linksection(".zgate") callconv(w32.WINAPI) w32.DWORD {
    const do_mask = zgateBegin(.ResumeThread);
    const ret = w32.ResumeThread(hThread);
    if (do_mask) zgateEnd();
    return ret;
}

fn zgateCreateThread(
    lpThreadAttributes: ?*w32.SECURITY_ATTRIBUTES,
    dwStackSize: w32.SIZE_T,
    lpStartAddress: w32.LPTHREAD_START_ROUTINE,
    lpParameter: ?w32.LPVOID,
    dwCreationFlags: w32.DWORD,
    lpThreadId: ?*w32.DWORD,
) linksection(".zgate") callconv(w32.WINAPI) ?w32.HANDLE {
    const do_mask = zgateBegin(.CreateThread);
    var ret: ?w32.HANDLE = null;
    if (!do_mask or (dwCreationFlags & w32.CREATE_SUSPENDED) != 0) {
        ret = w32.CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
        if (do_mask) zgateEnd();
    } else {
        ret = w32.CreateThread(
            lpThreadAttributes,
            dwStackSize,
            lpStartAddress,
            lpParameter,
            dwCreationFlags | w32.CREATE_SUSPENDED,
            lpThreadId,
        );
        if (do_mask) zgateEnd();
        if (ret) |h| _ = w32.ResumeThread(h);
    }
    return ret;
}

fn zgateCreateRemoteThread(
    hProcess: w32.HANDLE,
    lpThreadAttributes: ?*w32.SECURITY_ATTRIBUTES,
    dwStackSize: w32.SIZE_T,
    lpStartAddress: w32.LPTHREAD_START_ROUTINE,
    lpParameter: ?w32.LPVOID,
    dwCreationFlags: w32.DWORD,
    lpThreadId: ?*w32.DWORD,
) linksection(".zgate") callconv(w32.WINAPI) ?w32.HANDLE {
    const do_mask = zgateBegin(.CreateRemoteThread);
    const ret = w32.CreateRemoteThread(
        hProcess,
        lpThreadAttributes,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpThreadId,
    );
    if (do_mask) zgateEnd();
    return ret;
}
