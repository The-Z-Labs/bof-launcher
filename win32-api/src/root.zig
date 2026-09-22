const std = @import("std");
const windows = std.os.windows;
const builtin = @import("builtin");
const native_arch = builtin.cpu.arch;

pub const ATTACH_PARENT_PROCESS = 0xffff_ffff;

pub const ERROR_SUCCESS = 0;
pub const ERROR_INVALID_FUNCTION = 1;
pub const ERROR_INSUFFICIENT_BUFFER = 122;
pub const ERROR_MORE_DATA = 234;

pub const STATUS_SUCCESS = 0x00000000;
pub const STATUS_PROCESS_CLONED = 0x00000129;

pub const ACCESS_MASK = DWORD;
pub const OVERLAPPED = extern struct {
    Internal: ULONG_PTR,
    InternalHigh: ULONG_PTR,
    DUMMYUNIONNAME: extern union {
        DUMMYSTRUCTNAME: extern struct {
            Offset: DWORD,
            OffsetHigh: DWORD,
        },
        Pointer: ?PVOID,
    },
    hEvent: ?HANDLE,
};
pub const MEMORY_BASIC_INFORMATION = extern struct {
    BaseAddress: PVOID,
    AllocationBase: PVOID,
    AllocationProtect: DWORD,
    PartitionId: WORD,
    RegionSize: SIZE_T,
    State: DWORD,
    Protect: DWORD,
    Type: DWORD,
};
pub const SYSTEM_INFO = extern struct {
    anon1: extern union {
        dwOemId: DWORD,
        anon2: extern struct {
            wProcessorArchitecture: WORD,
            wReserved: WORD,
        },
    },
    dwPageSize: DWORD,
    lpMinimumApplicationAddress: LPVOID,
    lpMaximumApplicationAddress: LPVOID,
    dwActiveProcessorMask: DWORD_PTR,
    dwNumberOfProcessors: DWORD,
    dwProcessorType: DWORD,
    dwAllocationGranularity: DWORD,
    wProcessorLevel: WORD,
    wProcessorRevision: WORD,
};
pub const GUID = extern struct {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [8]u8,
};
pub const BOOL = c_int;
pub const PBOOL = *BOOL;
pub const TRUE = 1;
pub const FALSE = 0;
pub const OSVERSIONINFOW = extern struct {
    dwOSVersionInfoSize: ULONG,
    dwMajorVersion: ULONG,
    dwMinorVersion: ULONG,
    dwBuildNumber: ULONG,
    dwPlatformId: ULONG,
    szCSDVersion: [128]WCHAR,
};
pub const RTL_OSVERSIONINFOW = OSVERSIONINFOW;
pub const PSID = PVOID;
pub const PSECURITY_DESCRIPTOR = PVOID;
pub const NTSTATUS = u32;
pub const CLIENT_ID = extern struct {
    UniqueProcess: ?HANDLE,
    UniqueThread: ?HANDLE,
};
pub const UNICODE_STRING = extern struct {
    Length: USHORT,
    MaximumLength: USHORT,
    Buffer: ?[*]WCHAR,
};
pub const PCUNICODE_STRING = *const UNICODE_STRING;
pub const INFINITE = 4294967295;
pub const BOOLEAN = BYTE;
pub const HRESULT = c_long;
pub const HLOCAL = HANDLE;

pub const FLOATING_SAVE_AREA = switch (native_arch) {
    .x86 => extern struct {
        ControlWord: DWORD,
        StatusWord: DWORD,
        TagWord: DWORD,
        ErrorOffset: DWORD,
        ErrorSelector: DWORD,
        DataOffset: DWORD,
        DataSelector: DWORD,
        RegisterArea: [80]BYTE,
        Cr0NpxState: DWORD,
    },
    else => @compileError("FLOATING_SAVE_AREA only defined on x86"),
};

pub const M128A = switch (native_arch) {
    .x86_64 => extern struct {
        Low: ULONGLONG,
        High: LONGLONG,
    },
    else => @compileError("M128A only defined on x86_64"),
};

pub const XMM_SAVE_AREA32 = switch (native_arch) {
    .x86_64 => extern struct {
        ControlWord: WORD,
        StatusWord: WORD,
        TagWord: BYTE,
        Reserved1: BYTE,
        ErrorOpcode: WORD,
        ErrorOffset: DWORD,
        ErrorSelector: WORD,
        Reserved2: WORD,
        DataOffset: DWORD,
        DataSelector: WORD,
        Reserved3: WORD,
        MxCsr: DWORD,
        MxCsr_Mask: DWORD,
        FloatRegisters: [8]M128A,
        XmmRegisters: [16]M128A,
        Reserved4: [96]BYTE,
    },
    else => @compileError("XMM_SAVE_AREA32 only defined on x86_64"),
};

pub const NEON128 = switch (native_arch) {
    .thumb => extern struct {
        Low: ULONGLONG,
        High: LONGLONG,
    },
    .aarch64 => extern union {
        DUMMYSTRUCTNAME: extern struct {
            Low: ULONGLONG,
            High: LONGLONG,
        },
        D: [2]f64,
        S: [4]f32,
        H: [8]WORD,
        B: [16]BYTE,
    },
    else => @compileError("NEON128 only defined on aarch64"),
};

pub const CONTEXT = switch (native_arch) {
    .x86 => extern struct {
        ContextFlags: DWORD,
        Dr0: DWORD,
        Dr1: DWORD,
        Dr2: DWORD,
        Dr3: DWORD,
        Dr6: DWORD,
        Dr7: DWORD,
        FloatSave: FLOATING_SAVE_AREA,
        SegGs: DWORD,
        SegFs: DWORD,
        SegEs: DWORD,
        SegDs: DWORD,
        Edi: DWORD,
        Esi: DWORD,
        Ebx: DWORD,
        Edx: DWORD,
        Ecx: DWORD,
        Eax: DWORD,
        Ebp: DWORD,
        Eip: DWORD,
        SegCs: DWORD,
        EFlags: DWORD,
        Esp: DWORD,
        SegSs: DWORD,
        ExtendedRegisters: [512]BYTE,
    },
    .x86_64 => extern struct {
        P1Home: DWORD64 align(16),
        P2Home: DWORD64,
        P3Home: DWORD64,
        P4Home: DWORD64,
        P5Home: DWORD64,
        P6Home: DWORD64,
        ContextFlags: DWORD,
        MxCsr: DWORD,
        SegCs: WORD,
        SegDs: WORD,
        SegEs: WORD,
        SegFs: WORD,
        SegGs: WORD,
        SegSs: WORD,
        EFlags: DWORD,
        Dr0: DWORD64,
        Dr1: DWORD64,
        Dr2: DWORD64,
        Dr3: DWORD64,
        Dr6: DWORD64,
        Dr7: DWORD64,
        Rax: DWORD64,
        Rcx: DWORD64,
        Rdx: DWORD64,
        Rbx: DWORD64,
        Rsp: DWORD64,
        Rbp: DWORD64,
        Rsi: DWORD64,
        Rdi: DWORD64,
        R8: DWORD64,
        R9: DWORD64,
        R10: DWORD64,
        R11: DWORD64,
        R12: DWORD64,
        R13: DWORD64,
        R14: DWORD64,
        R15: DWORD64,
        Rip: DWORD64,
        DUMMYUNIONNAME: extern union {
            FltSave: XMM_SAVE_AREA32,
            FloatSave: XMM_SAVE_AREA32,
            DUMMYSTRUCTNAME: extern struct {
                Header: [2]M128A,
                Legacy: [8]M128A,
                Xmm0: M128A,
                Xmm1: M128A,
                Xmm2: M128A,
                Xmm3: M128A,
                Xmm4: M128A,
                Xmm5: M128A,
                Xmm6: M128A,
                Xmm7: M128A,
                Xmm8: M128A,
                Xmm9: M128A,
                Xmm10: M128A,
                Xmm11: M128A,
                Xmm12: M128A,
                Xmm13: M128A,
                Xmm14: M128A,
                Xmm15: M128A,
            },
        },
        VectorRegister: [26]M128A,
        VectorControl: DWORD64,
        DebugControl: DWORD64,
        LastBranchToRip: DWORD64,
        LastBranchFromRip: DWORD64,
        LastExceptionToRip: DWORD64,
        LastExceptionFromRip: DWORD64,
    },
    .thumb => extern struct {
        ContextFlags: ULONG,
        R0: ULONG,
        R1: ULONG,
        R2: ULONG,
        R3: ULONG,
        R4: ULONG,
        R5: ULONG,
        R6: ULONG,
        R7: ULONG,
        R8: ULONG,
        R9: ULONG,
        R10: ULONG,
        R11: ULONG,
        R12: ULONG,
        Sp: ULONG,
        Lr: ULONG,
        Pc: ULONG,
        Cpsr: ULONG,
        Fpcsr: ULONG,
        Padding: ULONG,
        DUMMYUNIONNAME: extern union {
            Q: [16]NEON128,
            D: [32]ULONGLONG,
            S: [32]ULONG,
        },
        Bvr: [8]ULONG,
        Bcr: [8]ULONG,
        Wvr: [1]ULONG,
        Wcr: [1]ULONG,
        Padding2: [2]ULONG,
    },
    .aarch64 => extern struct {
        ContextFlags: ULONG align(16),
        Cpsr: ULONG,
        DUMMYUNIONNAME: extern union {
            DUMMYSTRUCTNAME: extern struct {
                X0: DWORD64,
                X1: DWORD64,
                X2: DWORD64,
                X3: DWORD64,
                X4: DWORD64,
                X5: DWORD64,
                X6: DWORD64,
                X7: DWORD64,
                X8: DWORD64,
                X9: DWORD64,
                X10: DWORD64,
                X11: DWORD64,
                X12: DWORD64,
                X13: DWORD64,
                X14: DWORD64,
                X15: DWORD64,
                X16: DWORD64,
                X17: DWORD64,
                X18: DWORD64,
                X19: DWORD64,
                X20: DWORD64,
                X21: DWORD64,
                X22: DWORD64,
                X23: DWORD64,
                X24: DWORD64,
                X25: DWORD64,
                X26: DWORD64,
                X27: DWORD64,
                X28: DWORD64,
                Fp: DWORD64,
                Lr: DWORD64,
            },
            X: [31]DWORD64,
        },
        Sp: DWORD64,
        Pc: DWORD64,
        V: [32]NEON128,
        Fpcr: DWORD,
        Fpsr: DWORD,
        Bcr: [8]DWORD,
        Bvr: [8]DWORD64,
        Wcr: [2]DWORD,
        Wvr: [2]DWORD64,
    },
    else => @compileError("CONTEXT is not defined for this architecture"),
};
pub const LPTHREAD_START_ROUTINE = *const fn (LPVOID) callconv(.winapi) DWORD;
pub const WNDENUMPROC = *const fn (HWND, LPARAM) callconv(.winapi) BOOL;
pub const FILE_BOTH_DIR_INFORMATION = extern struct {
    NextEntryOffset: ULONG,
    FileIndex: ULONG,
    CreationTime: LARGE_INTEGER,
    LastAccessTime: LARGE_INTEGER,
    LastWriteTime: LARGE_INTEGER,
    ChangeTime: LARGE_INTEGER,
    EndOfFile: LARGE_INTEGER,
    AllocationSize: LARGE_INTEGER,
    FileAttributes: ULONG,
    FileNameLength: ULONG,
    EaSize: ULONG,
    ShortNameLength: CHAR,
    ShortName: [12]WCHAR,
    FileName: [1]WCHAR,
};
pub const FILE_BOTH_DIRECTORY_INFORMATION = FILE_BOTH_DIR_INFORMATION;
pub const BYTE = u8;
pub const CHAR = u8;
pub const UCHAR = u8;
pub const FLOAT = f32;
pub const HANDLE = *anyopaque;
pub const PHANDLE = *HANDLE;
pub const HCRYPTPROV = ULONG_PTR;
pub const ATOM = u16;
pub const HBRUSH = *opaque {};
pub const HCURSOR = *opaque {};
pub const HICON = *opaque {};
pub const HINSTANCE = *opaque {};
pub const HMENU = *opaque {};
pub const HMODULE = *opaque {};
pub const HWND = *opaque {};
pub const HDC = *opaque {};
pub const HGLRC = *opaque {};
pub const FARPROC = *opaque {};
pub const PROC = *opaque {};
pub const INT = c_int;
pub const LPCSTR = [*:0]const CHAR;
pub const LPCVOID = *const anyopaque;
pub const LPSTR = [*:0]CHAR;
pub const LPVOID = *anyopaque;
pub const LPWSTR = [*:0]WCHAR;
pub const LPCWSTR = [*:0]const WCHAR;
pub const PVOID = *anyopaque;
pub const PWSTR = [*:0]WCHAR;
pub const PCWSTR = [*:0]const WCHAR;
/// Allocated by SysAllocString, freed by SysFreeString
pub const BSTR = [*:0]WCHAR;
pub const SIZE_T = usize;
pub const UINT = c_uint;
pub const ULONG_PTR = usize;
pub const LONG_PTR = isize;
pub const DWORD_PTR = ULONG_PTR;
pub const WCHAR = u16;
pub const WORD = u16;
pub const DWORD = u32;
pub const DWORD64 = u64;
pub const LARGE_INTEGER = i64;
pub const PLARGE_INTEGER = *LARGE_INTEGER;
pub const ULARGE_INTEGER = u64;
pub const USHORT = u16;
pub const SHORT = i16;
pub const ULONG = u32;
pub const PULONG = *ULONG;
pub const LONG = i32;
pub const ULONG64 = u64;
pub const ULONGLONG = u64;
pub const LONGLONG = i64;
pub const LANGID = c_ushort;
pub const COLORREF = DWORD;

pub const LPARAM = LONG_PTR;

pub const OBJ_INHERIT = 0x00000002;
pub const OBJ_PERMANENT = 0x00000010;
pub const OBJ_EXCLUSIVE = 0x00000020;
pub const OBJ_CASE_INSENSITIVE = 0x00000040;
pub const OBJ_OPENIF = 0x00000080;
pub const OBJ_OPENLINK = 0x00000100;
pub const OBJ_KERNEL_HANDLE = 0x00000200;
pub const OBJ_VALID_ATTRIBUTES = 0x000003F2;

pub const AI = packed struct(u32) {
    PASSIVE: bool = false,
    CANONNAME: bool = false,
    NUMERICHOST: bool = false,
    NUMERICSERV: bool = false,
    DNS_ONLY: bool = false,
    _5: u3 = 0,
    ALL: bool = false,
    _9: u1 = 0,
    ADDRCONFIG: bool = false,
    V4MAPPED: bool = false,
    _12: u2 = 0,
    NON_AUTHORITATIVE: bool = false,
    SECURE: bool = false,
    RETURN_PREFERRED_NAMES: bool = false,
    FQDN: bool = false,
    FILESERVER: bool = false,
    DISABLE_IDN_ENCODING: bool = false,
    _20: u10 = 0,
    RESOLUTION_HANDLE: bool = false,
    EXTENDED: bool = false,
};

pub const ADDRESS_FAMILY = u16;
pub const sockaddr = extern struct {
    family: ADDRESS_FAMILY,
    data: [14]u8,

    pub const SS_MAXSIZE = 128;
    pub const storage = extern struct {
        family: ADDRESS_FAMILY align(8),
        padding: [SS_MAXSIZE - @sizeOf(ADDRESS_FAMILY)]u8 = undefined,
    };

    /// IPv4 socket address
    pub const in = extern struct {
        family: ADDRESS_FAMILY = AF.INET,
        port: USHORT,
        addr: u32,
        zero: [8]u8 = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };

    /// IPv6 socket address
    pub const in6 = extern struct {
        family: ADDRESS_FAMILY = AF.INET6,
        port: USHORT,
        flowinfo: u32,
        addr: [16]u8,
        scope_id: u32,
    };

    /// UNIX domain socket address
    pub const un = extern struct {
        family: ADDRESS_FAMILY = AF.UNIX,
        path: [108]u8,
    };
};

pub const addrinfo = addrinfoa;

pub const addrinfoa = extern struct {
    flags: AI,
    family: i32,
    socktype: i32,
    protocol: i32,
    addrlen: usize,
    canonname: ?[*:0]u8,
    addr: ?*sockaddr,
    next: ?*addrinfo,
};
pub const WSABUF = extern struct {
    len: ULONG,
    buf: [*]u8,
};
pub const LPWSAOVERLAPPED_COMPLETION_ROUTINE = *const fn (
    dwError: u32,
    cbTransferred: u32,
    lpOverlapped: *OVERLAPPED,
    dwFlags: u32,
) callconv(.winapi) void;

pub const WSAPOLLFD = pollfd;

pub const pollfd = extern struct {
    fd: SOCKET,
    events: SHORT,
    revents: SHORT,
};
pub const IO_STATUS_BLOCK = extern struct {
    // "DUMMYUNIONNAME" expands to "u"
    u: extern union {
        Status: NTSTATUS,
        Pointer: ?*anyopaque,
    },
    Information: ULONG_PTR,
};
pub const PIO_STATUS_BLOCK = *IO_STATUS_BLOCK;
pub const PIO_APC_ROUTINE = *const fn (PVOID, *IO_STATUS_BLOCK, ULONG) callconv(.winapi) void;
pub const WinsockError = u16;
pub const WAIT_FAILED = 0xffff_ffff;

pub const MEM_COMMIT = 0x1000;
pub const MEM_RESERVE = 0x2000;
pub const MEM_FREE = 0x10000;
pub const MEM_RESET = 0x80000;
pub const MEM_RESET_UNDO = 0x1000000;
pub const MEM_LARGE_PAGES = 0x20000000;
pub const MEM_PHYSICAL = 0x400000;
pub const MEM_TOP_DOWN = 0x100000;
pub const MEM_WRITE_WATCH = 0x200000;
pub const MEM_RESERVE_PLACEHOLDER = 0x00040000;
pub const MEM_PRESERVE_PLACEHOLDER = 0x00000400;

pub const MEM_COALESCE_PLACEHOLDERS = 0x1;
pub const MEM_RESERVE_PLACEHOLDERS = 0x2;
pub const MEM_DECOMMIT = 0x4000;
pub const MEM_RELEASE = 0x8000;

pub const PAGE_EXECUTE = 0x10;
pub const PAGE_EXECUTE_READ = 0x20;
pub const PAGE_EXECUTE_READWRITE = 0x40;
pub const PAGE_EXECUTE_WRITECOPY = 0x80;
pub const PAGE_NOACCESS = 0x01;
pub const PAGE_READONLY = 0x02;
pub const PAGE_READWRITE = 0x04;
pub const PAGE_WRITECOPY = 0x08;
pub const PAGE_TARGETS_INVALID = 0x40000000;
pub const PAGE_TARGETS_NO_UPDATE = 0x40000000;
pub const PAGE_GUARD = 0x100;
pub const PAGE_NOCACHE = 0x200;
pub const PAGE_WRITECOMBINE = 0x400;

pub const SECURITY_NT_AUTHORITY = 5;
pub const DOMAIN_ALIAS_RID_ADMINS = 544;
pub const SECURITY_BUILTIN_DOMAIN_RID = 32;

pub const READ_CONTROL = 0x00020000;

pub const STANDARD_RIGHTS_REQUIRED = 0x000F0000;
pub const SYNCHRONIZE = 0x00100000;

pub const STANDARD_RIGHTS_READ = READ_CONTROL;
pub const STANDARD_RIGHTS_WRITE = READ_CONTROL;
pub const STANDARD_RIGHTS_EXECUTE = READ_CONTROL;

pub const PROCESS_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xffff;
pub const PROCESS_CREATE_THREAD = 0x0002;
pub const PROCESS_VM_OPERATION = 0x0008;
pub const PROCESS_VM_READ = 0x0010;
pub const PROCESS_VM_WRITE = 0x0020;

pub const JOB_OBJECT_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3F;

pub const STANDARD_RIGHTS_ALL = 0x001F0000;

pub const SPECIFIC_RIGHTS_ALL = 0x0000FFFF;

pub const PROCESS_CREATE_FLAGS_INHERIT_HANDLES = 0x00000004;
pub const PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT = 0x00000100;

pub const OBJECT_INFORMATION_CLASS = enum(c_int) {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2,
    ObjectTypesInformation = 3,
    ObjectHandleFlagInformation = 4,
    ObjectSessionInformation = 5,
    MaxObjectInfoClass,
};

pub const FS_INFORMATION_CLASS = enum(c_int) {
    FileFsVolumeInformation = 1,
    FileFsLabelInformation,
    FileFsSizeInformation,
    FileFsDeviceInformation,
    FileFsAttributeInformation,
    FileFsControlInformation,
    FileFsFullSizeInformation,
    FileFsObjectIdInformation,
    FileFsDriverPathInformation,
    FileFsVolumeFlagsInformation,
    FileFsSectorSizeInformation,
    FileFsDataCopyInformation,
    FileFsMetadataSizeInformation,
    FileFsFullSizeInformationEx,
    FileFsGuidInformation,
    FileFsMaximumInformation,
};

pub const FILE_INFORMATION_CLASS = enum(c_int) {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileValidDataLengthInformation,
    FileShortNameInformation,
    FileIoCompletionNotificationInformation,
    FileIoStatusBlockRangeInformation,
    FileIoPriorityHintInformation,
    FileSfioReserveInformation,
    FileSfioVolumeInformation,
    FileHardLinkInformation,
    FileProcessIdsUsingFileInformation,
    FileNormalizedNameInformation,
    FileNetworkPhysicalNameInformation,
    FileIdGlobalTxDirectoryInformation,
    FileIsRemoteDeviceInformation,
    FileUnusedInformation,
    FileNumaNodeInformation,
    FileStandardLinkInformation,
    FileRemoteProtocolInformation,
    FileRenameInformationBypassAccessCheck,
    FileLinkInformationBypassAccessCheck,
    FileVolumeNameInformation,
    FileIdInformation,
    FileIdExtdDirectoryInformation,
    FileReplaceCompletionInformation,
    FileHardLinkFullIdInformation,
    FileIdExtdBothDirectoryInformation,
    FileDispositionInformationEx,
    FileRenameInformationEx,
    FileRenameInformationExBypassAccessCheck,
    FileDesiredStorageClassInformation,
    FileStatInformation,
    FileMemoryPartitionInformation,
    FileStatLxInformation,
    FileCaseSensitiveInformation,
    FileLinkInformationEx,
    FileLinkInformationExBypassAccessCheck,
    FileStorageReserveIdInformation,
    FileCaseSensitiveInformationForceAccessCheck,
    FileMaximumInformation,
};

pub const TOKEN_ASSIGN_PRIMARY = 0x0001;
pub const TOKEN_DUPLICATE = 0x0002;
pub const TOKEN_IMPERSONATE = 0x0004;
pub const TOKEN_QUERY = 0x0008;
pub const TOKEN_QUERY_SOURCE = 0x0010;
pub const TOKEN_ADJUST_PRIVILEGES = 0x0020;
pub const TOKEN_ADJUST_GROUPS = 0x0040;
pub const TOKEN_ADJUST_DEFAULT = 0x0080;
pub const TOKEN_ADJUST_SESSIONID = 0x0100;

pub const TOKEN_READ = STANDARD_RIGHTS_READ | TOKEN_QUERY;

pub const TOKEN_INFORMATION_CLASS = enum(c_int) {
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids,
    TokenSessionId,
    TokenGroupsAndPrivileges,
    TokenSessionReference,
    TokenSandBoxInert,
    TokenAuditPolicy,
    TokenOrigin,
    TokenElevationType,
    TokenLinkedToken,
    TokenElevation,
    TokenHasRestrictions,
    TokenAccessInformation,
    TokenVirtualizationAllowed,
    TokenVirtualizationEnabled,
    TokenIntegrityLevel,
    TokenUIAccess,
    TokenMandatoryPolicy,
    TokenLogonSid,
    TokenIsAppContainer,
    TokenCapabilities,
    TokenAppContainerSid,
    TokenAppContainerNumber,
    TokenUserClaimAttributes,
    TokenDeviceClaimAttributes,
    TokenRestrictedUserClaimAttributes,
    TokenRestrictedDeviceClaimAttributes,
    TokenDeviceGroups,
    TokenRestrictedDeviceGroups,
    TokenSecurityAttributes,
    TokenIsRestricted,
    TokenProcessTrustLevel,
    TokenPrivateNameSpace,
    TokenSingletonAttributes,
    TokenBnoIsolation,
    TokenChildProcessFlags,
    TokenIsLessPrivilegedAppContainer,
    TokenIsSandboxed,
    MaxTokenInfoClass, // MaxTokenInfoClass should always be the last enum
};

pub const TOKEN_USER = extern struct {
    User: SID_AND_ATTRIBUTES,
};

pub const MAX_PROTOCOL_CHAIN = 7;
pub const WSAPROTOCOLCHAIN = extern struct {
    ChainLen: c_int,
    ChainEntries: [MAX_PROTOCOL_CHAIN]DWORD,
};

pub const SOCKET = *opaque {};

pub const WSAPROTOCOL_LEN = 255;
pub const WSAPROTOCOL_INFOW = extern struct {
    dwServiceFlags1: DWORD,
    dwServiceFlags2: DWORD,
    dwServiceFlags3: DWORD,
    dwServiceFlags4: DWORD,
    dwProviderFlags: DWORD,
    ProviderId: GUID,
    dwCatalogEntryId: DWORD,
    ProtocolChain: WSAPROTOCOLCHAIN,
    iVersion: c_int,
    iAddressFamily: c_int,
    iMaxSockAddr: c_int,
    iMinSockAddr: c_int,
    iSocketType: c_int,
    iProtocol: c_int,
    iProtocolMaxOffset: c_int,
    iNetworkByteOrder: c_int,
    iSecurityScheme: c_int,
    dwMessageSize: DWORD,
    dwProviderReserved: DWORD,
    szProtocol: [WSAPROTOCOL_LEN + 1]WCHAR,
};

pub const WSADESCRIPTION_LEN = 256;
pub const WSASYS_STATUS_LEN = 128;
pub const WSADATA = if (@sizeOf(usize) == @sizeOf(u64))
    extern struct {
        wVersion: WORD,
        wHighVersion: WORD,
        iMaxSockets: u16,
        iMaxUdpDg: u16,
        lpVendorInfo: *u8,
        szDescription: [WSADESCRIPTION_LEN + 1]u8,
        szSystemStatus: [WSASYS_STATUS_LEN + 1]u8,
    }
else
    extern struct {
        wVersion: WORD,
        wHighVersion: WORD,
        szDescription: [WSADESCRIPTION_LEN + 1]u8,
        szSystemStatus: [WSASYS_STATUS_LEN + 1]u8,
        iMaxSockets: u16,
        iMaxUdpDg: u16,
        lpVendorInfo: *u8,
    };

pub const SECTION_IMAGE_INFORMATION = extern struct {
    TransferAddress: ?PVOID,
    ZeroBits: ULONG,
    MaximumStackSize: SIZE_T,
    CommittedStackSize: SIZE_T,
    SubSystemType: ULONG,
    U0: extern union {
        S: extern struct {
            SubSystemMinorVersion: USHORT,
            SubSystemMajorVersion: USHORT,
        },
        SubSystemVersion: ULONG,
    },
    U1: extern union {
        S: extern struct {
            MajorOperatingSystemVersion: USHORT,
            MinorOperatingSystemVersion: USHORT,
        },
        OperatingSystemVersion: ULONG,
    },
    ImageCharacteristics: USHORT,
    DllCharacteristics: USHORT,
    Machine: USHORT,
    ImageContainsCode: BOOLEAN,
    U2: extern union {
        ImageFlags: UCHAR,
        S: packed struct(UCHAR) {
            ComPlusNativeReady: u1,
            ComPlusILOnly: u1,
            ImageDynamicallyRelocated: u1,
            ImageMappedFlat: u1,
            BaseBelow4gb: u1,
            ComPlusPrefer32bit: u1,
            Reserved: u2,
        },
    },
    LoaderFlags: ULONG,
    ImageFileSize: ULONG,
    CheckSum: ULONG,
};

pub const RTL_USER_PROCESS_INFORMATION = extern struct {
    Length: ULONG,
    ProcessHandle: ?HANDLE,
    ThreadHandle: ?HANDLE,
    ClientId: CLIENT_ID,
    ImageInformation: SECTION_IMAGE_INFORMATION,
};

pub const RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED = 0x00000001;
pub const RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES = 0x00000002;
pub const RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE = 0x00000004; // don't update synchronization objects

pub const SECURITY_ATTRIBUTES = extern struct {
    nLength: DWORD,
    lpSecurityDescriptor: ?*anyopaque,
    bInheritHandle: BOOL,
};

pub const AF = struct {
    pub const UNSPEC = 0;
    pub const UNIX = 1;
    pub const INET = 2;
    pub const IMPLINK = 3;
    pub const PUP = 4;
    pub const CHAOS = 5;
    pub const NS = 6;
    pub const IPX = 6;
    pub const ISO = 7;
    pub const ECMA = 8;
    pub const DATAKIT = 9;
    pub const CCITT = 10;
    pub const SNA = 11;
    pub const DECnet = 12;
    pub const DLI = 13;
    pub const LAT = 14;
    pub const HYLINK = 15;
    pub const APPLETALK = 16;
    pub const NETBIOS = 17;
    pub const VOICEVIEW = 18;
    pub const FIREFOX = 19;
    pub const UNKNOWN1 = 20;
    pub const BAN = 21;
    pub const ATM = 22;
    pub const INET6 = 23;
    pub const CLUSTER = 24;
    pub const @"12844" = 25;
    pub const IRDA = 26;
    pub const NETDES = 28;
    pub const MAX = 29;
    pub const TCNPROCESS = 29;
    pub const TCNMESSAGE = 30;
    pub const ICLFXBM = 31;
    pub const LINK = 33;
    pub const HYPERV = 34;
};

pub const SOCK = struct {
    pub const STREAM = 1;
    pub const DGRAM = 2;
    pub const RAW = 3;
    pub const RDM = 4;
    pub const SEQPACKET = 5;
};

pub const COINIT_MULTITHREADED = 0x0;
pub const COINIT_APARTMENTTHREADED = 0x2;
pub const COINIT_DISABLE_OLE1DDE = 0x4;
pub const COINIT_SPEED_OVER_MEMORY = 0x8;

pub const DLL_PROCESS_ATTACH = 1;
pub const DLL_PROCESS_DETACH = 0;

pub const CREATE_SUSPENDED = 0x4;

pub const OBJECT_ATTRIBUTES = extern struct {
    Length: ULONG,
    RootDirectory: ?HANDLE,
    ObjectName: ?*UNICODE_STRING,
    Attributes: ULONG,
    SecurityDescriptor: ?*anyopaque,
    SecurityQualityOfService: ?*anyopaque,
};
pub const POBJECT_ATTRIBUTES = *OBJECT_ATTRIBUTES;
pub const PCOBJECT_ATTRIBUTES = *const OBJECT_ATTRIBUTES;

pub const JOBOBJECTINFOCLASS = enum(c_int) {
    JobObjectBasicAccountingInformation = 1, // JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
    JobObjectBasicLimitInformation, // JOBOBJECT_BASIC_LIMIT_INFORMATION
    JobObjectBasicProcessIdList, // JOBOBJECT_BASIC_PROCESS_ID_LIST
    JobObjectBasicUIRestrictions, // JOBOBJECT_BASIC_UI_RESTRICTIONS
    JobObjectSecurityLimitInformation, // JOBOBJECT_SECURITY_LIMIT_INFORMATION
    JobObjectEndOfJobTimeInformation, // JOBOBJECT_END_OF_JOB_TIME_INFORMATION
    JobObjectAssociateCompletionPortInformation, // JOBOBJECT_ASSOCIATE_COMPLETION_PORT
    JobObjectBasicAndIoAccountingInformation, // JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION
    JobObjectExtendedLimitInformation, // JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    JobObjectJobSetInformation, // JOBOBJECT_JOBSET_INFORMATION
    JobObjectGroupInformation, // USHORT
    JobObjectNotificationLimitInformation, // JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION
    JobObjectLimitViolationInformation, // JOBOBJECT_LIMIT_VIOLATION_INFORMATION
    JobObjectGroupInformationEx, // GROUP_AFFINITY (ARRAY)
    JobObjectCpuRateControlInformation, // JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
    JobObjectCompletionFilter,
    JobObjectCompletionCounter,
    JobObjectFreezeInformation, // JOBOBJECT_FREEZE_INFORMATION
    JobObjectExtendedAccountingInformation, // JOBOBJECT_EXTENDED_ACCOUNTING_INFORMATION
    JobObjectWakeInformation, // JOBOBJECT_WAKE_INFORMATION
    JobObjectBackgroundInformation,
    JobObjectSchedulingRankBiasInformation,
    JobObjectTimerVirtualizationInformation,
    JobObjectCycleTimeNotification,
    JobObjectClearEvent,
    JobObjectInterferenceInformation, // JOBOBJECT_INTERFERENCE_INFORMATION
    JobObjectClearPeakJobMemoryUsed,
    JobObjectMemoryUsageInformation, // JOBOBJECT_MEMORY_USAGE_INFORMATION // JOBOBJECT_MEMORY_USAGE_INFORMATION_V2
    JobObjectSharedCommit,
    JobObjectContainerId,
    JobObjectIoRateControlInformation,
    JobObjectNetRateControlInformation, // JOBOBJECT_NET_RATE_CONTROL_INFORMATION
    JobObjectNotificationLimitInformation2, // JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_2
    JobObjectLimitViolationInformation2, // JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2
    JobObjectCreateSilo,
    JobObjectSiloBasicInformation, // SILOOBJECT_BASIC_INFORMATION
    JobObjectSiloRootDirectory, // SILOOBJECT_ROOT_DIRECTORY
    JobObjectServerSiloBasicInformation, // SERVERSILO_BASIC_INFORMATION
    JobObjectServerSiloUserSharedData, // SILO_USER_SHARED_DATA
    JobObjectServerSiloInitialize,
    JobObjectServerSiloRunningState,
    JobObjectIoAttribution,
    JobObjectMemoryPartitionInformation,
    JobObjectContainerTelemetryId,
    JobObjectSiloSystemRoot,
    JobObjectEnergyTrackingState, // JOBOBJECT_ENERGY_TRACKING_STATE
    JobObjectThreadImpersonationInformation,
    JobObjectIoPriorityLimit,
    JobObjectPagePriorityLimit,
    MaxJobObjectInfoClass,
};

pub const IO_COUNTERS = extern struct {
    ReadOperationCount: ULONGLONG,
    WriteOperationCount: ULONGLONG,
    OtherOperationCount: ULONGLONG,
    ReadTransferCount: ULONGLONG,
    WriteTransferCount: ULONGLONG,
    OtherTransferCount: ULONGLONG,
};

pub const JOBOBJECT_BASIC_LIMIT_INFORMATION = extern struct {
    PerProcessUserTimeLimit: LARGE_INTEGER,
    PerJobUserTimeLimit: LARGE_INTEGER,
    LimitFlags: DWORD,
    MinimumWorkingSetSize: SIZE_T,
    MaximumWorkingSetSize: SIZE_T,
    ActiveProcessLimit: DWORD,
    Affinity: ULONG_PTR,
    PriorityClass: DWORD,
    SchedulingClass: DWORD,
};

pub const JOBOBJECT_EXTENDED_LIMIT_INFORMATION = extern struct {
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    IoInfo: IO_COUNTERS,
    ProcessMemoryLimit: SIZE_T,
    JobMemoryLimit: SIZE_T,
    PeakProcessMemoryUsed: SIZE_T,
    PeakJobMemoryUsed: SIZE_T,
};

pub const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400;
pub const JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800;
pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;

pub const WAIT_OBJECT_0 = 0;

pub const PS_CREATE_STATE = enum(u32) {
    InitialState,
    FailOnFileOpen,
    FailOnSectionCreate,
    FailExeFormat,
    FailMachineMismatch,
    FailExeName, // Debugger specified
    Success,
    MaximumStates,
};

pub const PS_CREATE_INFO = extern struct {
    Size: SIZE_T,
    State: PS_CREATE_STATE,
    U: extern union {
        InitialState: extern struct {
            U: extern union {
                InitFlags: ULONG,
                S: packed struct(ULONG) {
                    WriteOutputOnExit: u1,
                    DetectManifest: u1,
                    IFEOSkipDebugger: u1,
                    IFEODoNotPropagateKeyState: u1,
                    SpareBits1: u4,
                    SpareBits2: u8,
                    ProhibitedImageCharacteristics: u16,
                },
            },
        },
        FailSection: extern struct {
            FileHandle: HANDLE,
        },
        ExeFormat: extern struct {
            DllCharacteristics: USHORT,
        },
        ExeName: extern struct {
            IFEOKey: HANDLE,
        },
        SuccessState: extern struct {
            U: extern union {
                OutputFlags: ULONG,
                S: packed struct(ULONG) {
                    ProtectedProcess: u1,
                    AddressSpaceOverride: u1,
                    DevOverrideEnabled: u1, // from Image File Execution Options
                    ManifestDetected: u1,
                    ProtectedProcessLight: u1,
                    SpareBits1: u3,
                    SpareBits2: u8,
                    SpareBits3: u16,
                },
            },
            FileHandle: HANDLE,
            SectionHandle: HANDLE,
            UserProcessParametersNative: ULONGLONG,
            UserProcessParametersWow64: ULONG,
            CurrentParameterFlags: ULONG,
            PebAddressNative: ULONGLONG,
            PebAddressWow64: ULONG,
            ManifestAddress: ULONGLONG,
            ManifestSize: ULONG,
        },
    },
};

pub const MB_ICONEXCLAMATION = 0x00000030;
pub const MB_ICONASTERISK = 0x00000040;
pub const MB_SYSTEMMODAL = 0x00001000;

pub const IMAGE_DOS_HEADER = extern struct {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [4]u16,
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [10]u16,
    e_lfanew: i32,
};

pub const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: u32,
    Size: u32,
};

pub const IMAGE_FILE_HEADER = extern struct {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
};

pub const IMAGE_OPTIONAL_HEADER32 = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    BaseOfData: u32,
    ImageBase: u32,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u32,
    SizeOfStackCommit: u32,
    SizeOfHeapReserve: u32,
    SizeOfHeapCommit: u32,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

pub const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

const IMAGE_NT_HEADERS32 = extern struct {
    Signature: DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER32,
};

const IMAGE_NT_HEADERS64 = extern struct {
    Signature: DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

pub const IMAGE_NT_HEADERS = if (@sizeOf(usize) == 8) IMAGE_NT_HEADERS64 else IMAGE_NT_HEADERS32;

pub const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,
    AddressOfNames: u32,
    AddressOfNameOrdinals: u32,
};

pub const IMAGE_SECTION_HEADER = extern struct {
    Name: [8]u8,
    Misc: extern union {
        PhysicalAddress: u32,
        VirtualSize: u32,
    },
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,
};

pub const _SID_IDENTIFIER_AUTHORITY = extern struct {
    Value: [6]UCHAR = @import("std").mem.zeroes([6]u8),
};
pub const SID_IDENTIFIER_AUTHORITY = _SID_IDENTIFIER_AUTHORITY;
pub const PSID_IDENTIFIER_AUTHORITY = [*c]_SID_IDENTIFIER_AUTHORITY;

pub const SID_AND_ATTRIBUTES = extern struct {
    Sid: PSID,
};

comptime {
    std.debug.assert(@offsetOf(IMAGE_DOS_HEADER, "e_lfanew") == 60);
    std.debug.assert(@offsetOf(IMAGE_NT_HEADERS, "OptionalHeader") == 24);
    std.debug.assert(@offsetOf(IMAGE_EXPORT_DIRECTORY, "NumberOfFunctions") == 20);
    std.debug.assert(@offsetOf(IMAGE_SECTION_HEADER, "Misc") == 8);
    std.debug.assert(@offsetOf(IMAGE_SECTION_HEADER, "SizeOfRawData") == 16);
    std.debug.assert(@offsetOf(IMAGE_SECTION_HEADER, "PointerToLinenumbers") == 28);
    std.debug.assert(@offsetOf(IMAGE_SECTION_HEADER, "Characteristics") == 36);
}

pub const IMAGE_DIRECTORY_ENTRY_EXPORT = 0;

pub const EXTENDED_NAME_FORMAT = enum(u32) {
    NameUnknown = 0,
    NameFullyQualifiedDN = 1,
    NameSamCompatible = 2,
    NameDisplay = 3,
    NameUniqueId = 6,
    NameCanonical = 7,
    NameUserPrincipal = 8,
    NameCanonicalEx = 9,
    NameServicePrincipal = 10,
    NameDnsDomain = 12,
    NameGivenName = 13,
    NameSurname = 14
};

//
// KERNEL32 function types
//
pub fn VirtualAlloc(
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    flAllocationType: DWORD,
    flProtect: DWORD,
) linksection(section_name) callconv(.winapi) ?LPVOID {
    const f = def(*const @TypeOf(VirtualAlloc), "VirtualAlloc", "kernel32");
    return f(lpAddress, dwSize, flAllocationType, flProtect);
}

pub fn VirtualQuery(
    lpAddress: ?LPVOID,
    lpBuffer: *MEMORY_BASIC_INFORMATION,
    dwLength: SIZE_T,
) linksection(section_name) callconv(.winapi) SIZE_T {
    const f = def(*const @TypeOf(VirtualQuery), "VirtualQuery", "kernel32");
    return f(lpAddress, lpBuffer, dwLength);
}

pub fn VirtualProtect(
    lpAddress: LPVOID,
    dwSize: SIZE_T,
    flNewProtect: DWORD,
    lpflOldProtect: *DWORD,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(VirtualProtect), "VirtualProtect", "kernel32");
    return f(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

pub fn VirtualFree(
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    dwFreeType: DWORD,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(VirtualFree), "VirtualFree", "kernel32");
    return f(lpAddress, dwSize, dwFreeType);
}

const section_name = ".winapi";

pub fn GetLastError() linksection(section_name) callconv(.winapi) DWORD {
    const f = def(*const @TypeOf(GetLastError), "GetLastError", "kernel32");
    return f();
}

pub fn SetLastError(dwErrCode: DWORD) linksection(section_name) callconv(.winapi) void {
    const f = def(*const @TypeOf(SetLastError), "SetLastError", "kernel32");
    f(dwErrCode);
}

pub fn Sleep(dwMilliseconds: DWORD) linksection(section_name) callconv(.winapi) void {
    const f = def(*const @TypeOf(Sleep), "Sleep", "kernel32");
    f(dwMilliseconds);
}

pub fn ExitProcess(uExitCode: UINT) linksection(section_name) callconv(.winapi) noreturn {
    const f = def(*const @TypeOf(ExitProcess), "ExitProcess", "kernel32");
    f(uExitCode);
}

pub fn GetCurrentProcess() linksection(section_name) callconv(.winapi) HANDLE {
    const f = def(*const @TypeOf(GetCurrentProcess), "GetCurrentProcess", "kernel32");
    return f();
}

pub fn WaitForSingleObject(
    hHandle: HANDLE,
    dwMilliseconds: DWORD
) linksection(section_name) callconv(.winapi) DWORD {
    const f = def(*const @TypeOf(WaitForSingleObject), "WaitForSingleObject", "kernel32");
    return f(hHandle, dwMilliseconds);
}

pub const PFN_ReadFile = *const fn (
    hFile: HANDLE,
    lpBuffer: LPVOID,
    nNumberOfBytesToRead: DWORD,
    lpNumberOfBytesRead: ?*DWORD,
    lpOverlapped: ?*OVERLAPPED,
) callconv(.winapi) BOOL;

pub const PFN_WriteFile = *const fn (
    hFile: HANDLE,
    lpBuffer: LPCVOID,
    nNumberOfBytesToWrite: DWORD,
    lpNumberOfBytesWritten: ?*DWORD,
    lpOverlapped: ?*OVERLAPPED,
) callconv(.winapi) BOOL;

pub const PFN_DuplicateHandle = *const fn (
    hSourceProcessHandle: HANDLE,
    hSourceHandle: HANDLE,
    hTargetProcessHandle: HANDLE,
    lpTargetHandle: *HANDLE,
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwOptions: DWORD,
) callconv(.winapi) BOOL;

pub const PFN_GetCurrentThreadId = *const fn () callconv(.winapi) DWORD;

pub const PFN_FreeLibrary = *const fn (hModule: HMODULE) callconv(.winapi) BOOL;

pub const PFN_CreateThread = *const fn (
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    dwStackSize: SIZE_T,
    lpStartAddress: LPTHREAD_START_ROUTINE,
    lpParameter: ?LPVOID,
    dwCreationFlags: DWORD,
    lpThreadId: ?*DWORD,
) callconv(.winapi) ?HANDLE;

pub const PFN_GetSystemInfo = *const fn (lpSystemInfo: *SYSTEM_INFO) callconv(.winapi) void;

pub const PFN_VirtualFreeEx = *const fn (
    hProcess: HANDLE,
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    dwFreeType: DWORD,
) callconv(.winapi) BOOL;

pub const PFN_GetModuleFileNameA = *const fn (
    hModule: ?HMODULE,
    lpFilename: LPSTR,
    nSize: DWORD,
) callconv(.winapi) DWORD;

pub const PFN_GetCurrentProcessId = *const fn () callconv(.winapi) DWORD;

pub const PFN_GetProcessId = *const fn (hProcess: HANDLE) callconv(.winapi) DWORD;

pub const PFN_GetCurrentThread = *const fn () callconv(.winapi) HANDLE;

pub const PFN_CloseHandle = *const fn (hObject: HANDLE) callconv(.winapi) BOOL;

pub const PFN_FlushInstructionCache = *const fn (
    hProcess: HANDLE,
    lpBaseAddress: ?LPCVOID,
    dwSize: SIZE_T,
) callconv(.winapi) BOOL;

pub const PFN_FreeConsole = *const fn () callconv(.winapi) BOOL;

pub const PFN_AttachConsole = *const fn (dwProcessId: DWORD) callconv(.winapi) BOOL;

pub const PFN_IsWow64Process = *const fn (
    hProcess: HANDLE,
    Wow64Process: *BOOL,
) callconv(.winapi) BOOL;

pub const PFN_GetExitCodeProcess = *const fn (
    hProcess: HANDLE,
    lpExitCode: *DWORD,
) callconv(.winapi) BOOL;

pub const PFN_GetModuleHandleA = *const fn (lpModuleName: ?LPCSTR) callconv(.winapi) ?HMODULE;

pub const PFN_LoadLibraryA = *const fn (lpLibFileName: LPCSTR) callconv(.winapi) ?HMODULE;

pub const PFN_GetProcAddress = *const fn (
    hModule: HMODULE,
    lpProcName: LPCSTR,
) callconv(.winapi) ?FARPROC;

pub const PFN_CreatePipe = *const fn (
    hReadPipe: *HANDLE,
    hWritePipe: *HANDLE,
    lpPipeAttributes: ?*SECURITY_ATTRIBUTES,
    nSize: DWORD,
) callconv(.winapi) BOOL;

pub const PFN_ResumeThread = *const fn (hThread: HANDLE) callconv(.winapi) DWORD;

pub const PFN_SuspendThread = *const fn (hThread: HANDLE) callconv(.winapi) DWORD;

pub const PFN_VirtualAllocEx = *const fn (
    hProcess: HANDLE,
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    flAllocationType: DWORD,
    flProtect: DWORD,
) callconv(.winapi) ?LPVOID;

pub const PFN_VirtualProtectEx = *const fn (
    hProcess: HANDLE,
    lpAddress: LPVOID,
    dwSize: SIZE_T,
    flNewProtect: DWORD,
    lpflOldProtect: *DWORD,
) callconv(.winapi) BOOL;

pub const PFN_CreateFileMappingA = *const fn (
    hFile: HANDLE,
    lpFileMappingAttributes: ?*SECURITY_ATTRIBUTES,
    flProtect: DWORD,
    dwMaximumSizeHigh: DWORD,
    dwMaximumSizeLow: DWORD,
    lpName: ?LPCSTR,
) callconv(.winapi) ?HANDLE;

pub const PFN_GetThreadContext = *const fn (
    hThread: HANDLE,
    lpContext: *CONTEXT,
) callconv(.winapi) BOOL;

pub const PFN_GetThreadId = *const fn (hThread: HANDLE) callconv(.winapi) DWORD;

pub const PFN_SetThreadContext = *const fn (
    hThread: HANDLE,
    lpContext: *const CONTEXT,
) callconv(.winapi) BOOL;

pub const PFN_MapViewOfFile = *const fn (
    hFileMappingObject: HANDLE,
    dwDesiredAccess: DWORD,
    dwFileOffsetHigh: DWORD,
    dwFileOffsetLow: DWORD,
    dwNumberOfBytesToMap: SIZE_T,
) callconv(.winapi) LPVOID;

pub const PFN_UnmapViewOfFile = *const fn (lpBaseAddress: LPCVOID) callconv(.winapi) BOOL;

pub const PFN_OpenProcess = *const fn (
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwProcessId: DWORD,
) callconv(.winapi) ?HANDLE;

pub const PFN_OpenThread = *const fn (
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwThreadId: DWORD,
) callconv(.winapi) ?HANDLE;

pub const PFN_WriteProcessMemory = *const fn (
    hProcess: HANDLE,
    lpBaseAddress: LPVOID,
    lpBuffer: LPCVOID,
    nSize: SIZE_T,
    lpNumberOfBytesWritten: ?*SIZE_T,
) callconv(.winapi) BOOL;

pub const PFN_ReadProcessMemory = *const fn (
    hProcess: HANDLE,
    lpBaseAddress: LPCVOID,
    lpBuffer: LPVOID,
    nSize: SIZE_T,
    lpNumberOfBytesRead: ?*SIZE_T,
) callconv(.winapi) BOOL;

pub const PFN_CreateRemoteThread = *const fn (
    hProcess: HANDLE,
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    dwStackSize: SIZE_T,
    lpStartAddress: LPTHREAD_START_ROUTINE,
    lpParameter: ?LPVOID,
    dwCreationFlags: DWORD,
    lpThreadId: ?*DWORD,
) callconv(.winapi) ?HANDLE;

pub const PFN_GetCurrentDirectoryW = *const fn (
    nBufferLength: DWORD,
    lpBuffer: ?[*]WCHAR,
) callconv(.winapi) DWORD;

pub const PFN_HeapAlloc = *const fn (
    hHeap: ?HANDLE,
    dwFlags: DWORD,
    dwBytes: SIZE_T,
) callconv(.winapi) ?LPVOID;

pub const PFN_HeapFree = *const fn (
    hHeap: ?HANDLE,
    dwFlags: DWORD,
    lpMem: ?LPVOID,
) callconv(.winapi) BOOL;

pub const PFN_GetProcessHeap = *const fn () callconv(.winapi) ?HANDLE;

pub const PFN_OutputDebugStringA = *const fn (LPCSTR) callconv(.winapi) void;

pub const PFN_GetFileSizeEx = *const fn (
    hFile: HANDLE,
    lpFileSize: *LARGE_INTEGER,
) callconv(.winapi) BOOL;

pub const PFN_SetFilePointerEx = *const fn (
    hFile: HANDLE,
    liDistanceToMove: LARGE_INTEGER,
    lpNewFilePointer: ?*LARGE_INTEGER,
    dwMoveMethod: DWORD,
) callconv(.winapi) BOOL;

pub const PFN_LocalFree = *const fn (hMem: HLOCAL) callconv(.winapi) ?HLOCAL;

//
// NTDLL function types
//
pub const PFN_RtlCloneUserProcess = *const fn (
    ProcessFlags: ULONG,
    ProcessSecurityDescriptor: ?PSECURITY_DESCRIPTOR,
    ThreadSecurityDescriptor: ?PSECURITY_DESCRIPTOR,
    DebugPort: ?HANDLE,
    ProcessInformation: *RTL_USER_PROCESS_INFORMATION,
) callconv(.winapi) NTSTATUS;

pub fn RtlGetVersion(
    lpVersionInformation: *RTL_OSVERSIONINFOW,
) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(RtlGetVersion), "RtlGetVersion", "ntdll");
    return f(lpVersionInformation);
}

pub const PFN_NtSuspendThread = *const fn (
    ThreadHandle: HANDLE,
    PreviousSuspendCount: ?*ULONG,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtTerminateThread = *const fn (
    ThreadHandle: ?HANDLE,
    ExitStatus: NTSTATUS,
) callconv(.winapi) NTSTATUS;

pub fn NtOpenProcess(
    ProcessHandle: *HANDLE,
    DesiredAccess: DWORD,
    ObjectAttributes: ?*OBJECT_ATTRIBUTES,
    ClientId: ?*CLIENT_ID,
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtOpenProcess), "NtOpenProcess", "ntdll");
    return f(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

pub const PFN_NtResumeProcess = *const fn (ProcessHandle: HANDLE) callconv(.winapi) NTSTATUS;

pub const PFN_NtSuspendProcess = *const fn (ProcessHandle: HANDLE) callconv(.winapi) NTSTATUS;

pub const PFN_NtCreateJobObject = *const fn (
    JobHandle: *HANDLE,
    DesiredAccess: DWORD,
    ObjectAttributes: ?*OBJECT_ATTRIBUTES,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtAssignProcessToJobObject = *const fn (
    JobHandle: HANDLE,
    ProcessHandle: HANDLE,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtTerminateJobObject = *const fn (
    JobHandle: HANDLE,
    ExitStatus: NTSTATUS,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtIsProcessInJob = *const fn (
    ProcessHandle: HANDLE,
    JobHandle: ?HANDLE,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtSetInformationJobObject = *const fn (
    JobHandle: HANDLE,
    JobObjectInformationClass: JOBOBJECTINFOCLASS,
    JobObjectInformation: PVOID,
    JobObjectInformationLength: ULONG,
) callconv(.winapi) NTSTATUS;

pub const PFN_RtlWow64EnableFsRedirection = *const fn (Wow64FsEnableRedirection: BOOLEAN) callconv(.winapi) NTSTATUS;

pub const PFN_NtCreateUserProcess = *const fn (
    ProcessHandle: *HANDLE,
    ThreadHandle: *HANDLE,
    ProcessDesiredAccess: DWORD,
    ThreadDesiredAccess: DWORD,
    ProcessObjectAttributes: ?*OBJECT_ATTRIBUTES,
    ThreadObjectAttributes: ?*OBJECT_ATTRIBUTES,
    ProcessFlags: ULONG,
    ThreadFlags: ULONG,
    ProcessParameters: ?PVOID,
    CreateInfo: *PS_CREATE_INFO,
    AttributeList: ?*anyopaque, // TODO: ?*PS_ATTRIBUTE_LIST,
) callconv(.winapi) NTSTATUS;

pub fn NtCreateFile(
    FileHandle: PHANDLE, // _Out_
    DesiredAccess: ACCESS_MASK, // _In_
    ObjectAttributes: PCOBJECT_ATTRIBUTES, // _In_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    AllocationSize: ?PLARGE_INTEGER, // _In_opt_
    FileAttributes: ULONG, // _In_
    ShareAccess: ULONG, // _In_
    CreateDisposition: ULONG, // _In_
    CreateOptions: ULONG, // _In_
    EaBuffer: ?PVOID, // _In_reads_bytes_opt_(EaLength)
    EaLength: ULONG, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtCreateFile), "NtCreateFile", "ntdll");
    return f(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

pub fn NtDeviceIoControlFile(
    FileHandle: HANDLE, // _In_
    Event: ?HANDLE, // _In_opt_
    ApcRoutine: ?PIO_APC_ROUTINE, // _In_opt_
    ApcContext: ?PVOID, // _In_opt_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    IoControlCode: ULONG, // _In_
    InputBuffer: ?PVOID, // _In_reads_bytes_opt_(InputBufferLength)
    InputBufferLength: ULONG, // _In_
    OutputBuffer: ?PVOID, // _Out_writes_bytes_opt_(OutputBufferLength)
    OutputBufferLength: ULONG, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtDeviceIoControlFile), "NtDeviceIoControlFile", "ntdll");
    return f(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}

pub fn NtFsControlFile(
    FileHandle: HANDLE, // _In_
    Event: ?HANDLE, // _In_opt_
    ApcRoutine: ?PIO_APC_ROUTINE, // _In_opt_
    ApcContext: ?PVOID, // _In_opt_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    FsControlCode: ULONG, // _In_
    InputBuffer: ?PVOID, // _In_reads_bytes_opt_(InputBufferLength)
    InputBufferLength: ULONG, // _In_
    OutputBuffer: ?PVOID, // _Out_writes_bytes_opt_(OutputBufferLength)
    OutputBufferLength: ULONG, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtFsControlFile), "NtFsControlFile", "ntdll");
    return f(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FsControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}

pub fn NtLockFile(
    FileHandle: HANDLE, // _In_
    Event: ?HANDLE, // _In_opt_
    ApcRoutine: ?PIO_APC_ROUTINE, // _In_opt_
    ApcContext: ?PVOID, // _In_opt_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    ByteOffset: PLARGE_INTEGER, // _In_
    Length: PLARGE_INTEGER, // _In_
    Key: ULONG, // _In_
    FailImmediately: BOOLEAN, // _In_
    ExclusiveLock: BOOLEAN, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtLockFile), "NtLockFile", "ntdll");
    return f(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, ByteOffset, Length, Key, FailImmediately, ExclusiveLock);
}

pub fn NtUnlockFile(
    FileHandle: HANDLE, // _In_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    ByteOffset: PLARGE_INTEGER, // _In_
    Length: PLARGE_INTEGER, // _In_
    Key: ULONG, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtUnlockFile), "NtUnlockFile", "ntdll");
    return f(FileHandle, IoStatusBlock, ByteOffset, Length, Key);
}

pub fn NtQueryDirectoryFile(
    FileHandle: HANDLE, // _In_
    Event: ?HANDLE, // _In_opt_
    ApcRoutine: ?PIO_APC_ROUTINE, // _In_opt_
    ApcContext: ?PVOID, // _In_opt_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    FileInformation: PVOID, // _Out_writes_bytes_(Length)
    Length: ULONG, // _In_
    FileInformationClass: FILE_INFORMATION_CLASS, // _In_
    ReturnSingleEntry: BOOLEAN, // _In_
    FileName: ?PCUNICODE_STRING, // _In_opt_
    RestartScan: BOOLEAN, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtQueryDirectoryFile), "NtQueryDirectoryFile", "ntdll");
    return f(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
}

pub fn NtQueryInformationFile(
    FileHandle: HANDLE, // _In_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    FileInformation: PVOID, // _Out_writes_bytes_(Length)
    Length: ULONG, // _In_
    FileInformationClass: FILE_INFORMATION_CLASS, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtQueryInformationFile), "NtQueryInformationFile", "ntdll");
    return f(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

pub fn NtQueryVolumeInformationFile(
    FileHandle: HANDLE, // _In_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    FsInformation: PVOID, // _Out_writes_bytes_(Length)
    Length: ULONG, // _In_
    FsInformationClass: FS_INFORMATION_CLASS, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtQueryVolumeInformationFile), "NtQueryVolumeInformationFile", "ntdll");
    return f(FileHandle, IoStatusBlock, FsInformation, Length, FsInformationClass);
}

pub const FILE_BASIC_INFORMATION = extern struct {
    CreationTime: LARGE_INTEGER,
    LastAccessTime: LARGE_INTEGER,
    LastWriteTime: LARGE_INTEGER,
    ChangeTime: LARGE_INTEGER,
    FileAttributes: ULONG,
};
pub const PFILE_BASIC_INFORMATION = *FILE_BASIC_INFORMATION;

pub fn NtQueryAttributesFile(
    ObjectAttributes: PCOBJECT_ATTRIBUTES, // _In_
    FileAttributes: PFILE_BASIC_INFORMATION, // _Out_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtQueryAttributesFile), "NtQueryAttributesFile", "ntdll");
    return f(ObjectAttributes, FileAttributes);
}

pub fn NtSetInformationFile(
    FileHandle: HANDLE, // _In_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    FileInformation: PVOID, // _In_reads_bytes_(Length)
    Length: ULONG, // _In_
    FileInformationClass: FILE_INFORMATION_CLASS, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtSetInformationFile), "NtSetInformationFile", "ntdll");
    return f(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

pub fn NtReadFile(
    FileHandle: HANDLE, // _In_
    Event: ?HANDLE, // _In_opt_
    ApcRoutine: ?PIO_APC_ROUTINE, // _In_opt_
    ApcContext: ?PVOID, // _In_opt_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    Buffer: PVOID, // _Out_writes_bytes_(Length)
    Length: ULONG, // _In_
    ByteOffset: ?PLARGE_INTEGER, // _In_opt_
    Key: ?PULONG, // _In_opt_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtReadFile), "NtReadFile", "ntdll");
    return f(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

pub fn NtWriteFile(
    FileHandle: HANDLE, // _In_
    Event: ?HANDLE, // _In_opt_
    ApcRoutine: ?PIO_APC_ROUTINE, // _In_opt_
    ApcContext: ?PVOID, // _In_opt_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    Buffer: PVOID, // _In_reads_bytes_(Length)
    Length: ULONG, // _In_
    ByteOffset: ?PLARGE_INTEGER, // _In_opt_
    Key: ?PULONG, // _In_opt_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtWriteFile), "NtWriteFile", "ntdll");
    return f(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

pub const PFN_NtQueryObject = *const @TypeOf(std.os.windows.ntdll.NtQueryObject);
pub const PFN_NtClose = *const @TypeOf(std.os.windows.ntdll.NtClose);
pub const PFN_NtCreateNamedPipeFile = *const @TypeOf(std.os.windows.ntdll.NtCreateNamedPipeFile);
pub const PFN_NtWriteVirtualMemory = *const @TypeOf(std.os.windows.ntdll.NtWriteVirtualMemory);
pub const PFN_NtProtectVirtualMemory = *const @TypeOf(std.os.windows.ntdll.NtProtectVirtualMemory);
pub const PFN_RtlGetFullPathName_U = *const @TypeOf(std.os.windows.ntdll.RtlGetFullPathName_U);
pub const PFN_RtlGetSystemTimePrecise = *const @TypeOf(std.os.windows.ntdll.RtlGetSystemTimePrecise);
pub const PFN_NtTerminateProcess = *const @TypeOf(std.os.windows.ntdll.NtTerminateProcess);
pub const PFN_RtlSetCurrentDirectory_U = *const @TypeOf(std.os.windows.ntdll.RtlSetCurrentDirectory_U);
pub const PFN_NtCreateThreadEx = *const @TypeOf(std.os.windows.ntdll.NtCreateThreadEx);
pub const PFN_NtResumeThread = *const @TypeOf(std.os.windows.ntdll.NtResumeThread);

//
// ADVAPI32 function types
//
pub const PFN_OpenProcessToken = *const fn (
    ProcessHandle: HANDLE,
    DesiredAccess: DWORD,
    TokenHandle: *HANDLE,
) callconv(.winapi) BOOL;

pub const PFN_GetTokenInformation = *const fn (
    TokenHandle: HANDLE,
    TokenInformationClass: TOKEN_INFORMATION_CLASS,
    TokenInformation: ?*anyopaque,
    TokenInformationLength: DWORD,
    ReturnLength: *DWORD,
) callconv(.winapi) BOOL;

pub const PFN_CheckTokenMembership = *const fn (
    TokenHandle: ?HANDLE,
    SidToCheck: PSID,
    IsMember: PBOOL,
) callconv(.winapi) BOOL;

pub const PFN_AllocateAndInitializeSid = *const fn (
    pIdentifierAuthority: PSID_IDENTIFIER_AUTHORITY,
    nSubAuthorityCount: BYTE,
    nSubAuthority0: DWORD,
    nSubAuthority1: DWORD,
    nSubAuthority2: DWORD,
    nSubAuthority3: DWORD,
    nSubAuthority4: DWORD,
    nSubAuthority5: DWORD,
    nSubAuthority6: DWORD,
    nSubAuthority7: DWORD,
    pSid: *PSID,
) callconv(.winapi) BOOL;

pub const PFN_FreeSid = *const fn (
    pSid: PSID,
) callconv(.winapi) PVOID;

pub const PFN_ConvertSidToStringSidA = *const fn (
    pSid: PSID,
    pStringSid: *LPSTR,
) callconv(.winapi) BOOL;

pub const PFN_RtlGenRandom = *const fn (
    RandomBuffer: PVOID,
    RandomBufferLength: ULONG,
) callconv(.winapi) BOOL;

//
// USER32 function types
//
pub const PFN_MessageBoxA = *const fn (
    hWnd: ?HWND,
    lpText: ?LPCSTR,
    lpCaption: ?LPCSTR,
    uType: UINT,
) callconv(.winapi) i32;

pub const PFN_MessageBoxW = *const fn (
    hWnd: ?HWND,
    lpText: ?LPCWSTR,
    lpCaption: ?LPCWSTR,
    uType: UINT,
) callconv(.winapi) i32;

pub const PFN_EnumWindows = *const fn (
    lpEnumFunc: WNDENUMPROC,
    lParam: LPARAM,
) callconv(.winapi) BOOL;

pub const PFN_GetWindowThreadProcessId = *const fn (
    hWnd: HWND,
    lpdwProcessId: ?*DWORD,
) callconv(.winapi) DWORD;

pub const PFN_SetForegroundWindow = *const fn (hWnd: HWND) callconv(.winapi) BOOL;
pub const PFN_GetForegroundWindow = *const fn () callconv(.winapi) ?HWND;

//
// OLE32 function types
//
pub const PFN_CoInitializeEx = *const fn (
    pvReserved: ?LPVOID,
    dwCoInit: DWORD,
) callconv(.winapi) HRESULT;

pub const PFN_CoUninitialize = *const fn () callconv(.winapi) void;
pub const PFN_CoTaskMemAlloc = *const fn (size: SIZE_T) callconv(.winapi) ?LPVOID;
pub const PFN_CoTaskMemFree = *const fn (pv: LPVOID) callconv(.winapi) void;
pub const PFN_CoGetCurrentProcess = *const fn () callconv(.winapi) DWORD;
pub const PFN_CoGetCallerTID = *const fn (lpdwTID: *DWORD) callconv(.winapi) HRESULT;

//
// WS2_32 function types
//
pub const PFN_WSAStartup = *const fn (
    wVersionRequired: WORD,
    lpWSAData: *WSADATA,
) callconv(.winapi) i32;

pub const PFN_WSACleanup = *const fn () callconv(.winapi) i32;

pub const PFN_WSAGetLastError = *const fn () callconv(.winapi) WinsockError;

pub const PFN_WSASocketW = *const fn (
    af: i32,
    @"type": i32,
    protocol: i32,
    lpProtocolInfo: ?*WSAPROTOCOL_INFOW,
    g: u32,
    dwFlags: u32,
) callconv(.winapi) SOCKET;

pub const PFN_WSAPoll = *const fn (
    fdArray: [*]WSAPOLLFD,
    fds: u32,
    timeout: i32,
) callconv(.winapi) i32;

pub const PFN_WSAGetOverlappedResult = *const fn (
    s: SOCKET,
    lpOverlapped: *OVERLAPPED,
    lpcbTransfer: *DWORD,
    fWait: BOOL,
    lpdwFlags: *DWORD,
) callconv(.winapi) BOOL;

pub const PFN_WSASend = *const fn (
    s: SOCKET,
    lpBuffers: [*]WSABUF,
    dwBufferCount: u32,
    lpNumberOfBytesSent: ?*u32,
    dwFlags: u32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRounte: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub const PFN_WSASendTo = *const fn (
    s: SOCKET,
    lpBuffers: [*]WSABUF,
    dwBufferCount: u32,
    lpNumberOfBytesSent: ?*u32,
    dwFlags: u32,
    lpTo: ?*const sockaddr,
    iToLen: i32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRounte: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub const PFN_WSARecv = *const fn (
    s: SOCKET,
    lpBuffers: [*]WSABUF,
    dwBuffercount: u32,
    lpNumberOfBytesRecvd: ?*u32,
    lpFlags: *u32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRoutine: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub const PFN_WSARecvFrom = *const fn (
    s: SOCKET,
    lpBuffers: [*]WSABUF,
    dwBuffercount: u32,
    lpNumberOfBytesRecvd: ?*u32,
    lpFlags: *u32,
    lpFrom: ?*sockaddr,
    lpFromlen: ?*i32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRoutine: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub const PFN_closesocket = *const fn (s: SOCKET) callconv(.winapi) i32;

pub const PFN_getaddrinfo = *const fn (
    pNodeName: ?[*:0]const u8,
    pServiceName: ?[*:0]const u8,
    pHints: ?*const addrinfoa,
    ppResult: *?*addrinfoa,
) callconv(.winapi) i32;

pub const PFN_freeaddrinfo = *const fn (pAddrInfo: ?*addrinfoa) callconv(.winapi) void;

pub const PFN_bind = *const fn (
    s: SOCKET,
    name: *const sockaddr,
    namelen: i32,
) callconv(.winapi) i32;

pub const PFN_connect = *const fn (
    s: SOCKET,
    name: *const sockaddr,
    namelen: i32,
) callconv(.winapi) i32;

pub const PFN_ioctlsocket = *const fn (
    s: SOCKET,
    cmd: i32,
    argp: *u32,
) callconv(.winapi) i32;

pub const PFN_getsockopt = *const fn (
    s: SOCKET,
    level: i32,
    optname: i32,
    optval: [*]u8,
    optlen: *i32,
) callconv(.winapi) i32;

pub const PFN_setsockopt = *const fn (
    s: SOCKET,
    level: i32,
    optname: i32,
    optval: ?[*]const u8,
    optlen: i32,
) callconv(.winapi) i32;

//
// SECUR_32 function types
//
pub const PFN_GetUserNameExA = *const fn (
    NameFormat: EXTENDED_NAME_FORMAT,
    lpNameBuffer: ?LPSTR,
    nSize: *ULONG,
) callconv(.winapi) BOOLEAN;

//
// Define WIN32 function
//
const bof = @import("options").bof;

pub fn def(
    comptime T: type,
    comptime funcname: []const u8,
    comptime libname: []const u8,
) if (@import("options").define_functions) T else void {
    return if (@import("options").define_functions)
        @extern(T, .{
            .name = if (bof) libname ++ "$" ++ funcname else funcname,
            .is_dll_import = true, // __declspec(dllimport)
        })
    else {};
}

pub fn init() void {
    GetCurrentThreadId = def(PFN_GetCurrentThreadId, "GetCurrentThreadId", "kernel32");
    FreeLibrary = def(PFN_FreeLibrary, "FreeLibrary", "kernel32");
    CreateThread = def(PFN_CreateThread, "CreateThread", "kernel32");
    GetSystemInfo = def(PFN_GetSystemInfo, "GetSystemInfo", "kernel32");
    VirtualFreeEx = def(PFN_VirtualFreeEx, "VirtualFreeEx", "kernel32");
    WriteFile = def(PFN_WriteFile, "WriteFile", "kernel32");
    DuplicateHandle = def(PFN_DuplicateHandle, "DuplicateHandle", "kernel32");
    ReadFile = def(PFN_ReadFile, "ReadFile", "kernel32");
    GetModuleFileNameA = def(PFN_GetModuleFileNameA, "GetModuleFileNameA", "kernel32");
    GetCurrentProcessId = def(PFN_GetCurrentProcessId, "GetCurrentProcessId", "kernel32");
    GetProcessId = def(PFN_GetProcessId, "GetProcessId", "kernel32");
    GetCurrentThread = def(PFN_GetCurrentThread, "GetCurrentThread", "kernel32");
    CloseHandle = def(PFN_CloseHandle, "CloseHandle", "kernel32");
    FlushInstructionCache = def(PFN_FlushInstructionCache, "FlushInstructionCache", "kernel32");
    FreeConsole = def(PFN_FreeConsole, "FreeConsole", "kernel32");
    AttachConsole = def(PFN_AttachConsole, "AttachConsole", "kernel32");
    IsWow64Process = def(PFN_IsWow64Process, "IsWow64Process", "kernel32");
    GetExitCodeProcess = def(PFN_GetExitCodeProcess, "GetExitCodeProcess", "kernel32");
    GetModuleHandleA = def(PFN_GetModuleHandleA, "GetModuleHandleA", "kernel32");
    LoadLibraryA = def(PFN_LoadLibraryA, "LoadLibraryA", "kernel32");
    GetProcAddress = def(PFN_GetProcAddress, "GetProcAddress", "kernel32");
    CreatePipe = def(PFN_CreatePipe, "CreatePipe", "kernel32");
    ResumeThread = def(PFN_ResumeThread, "ResumeThread", "kernel32");
    SuspendThread = def(PFN_ResumeThread, "SuspendThread", "kernel32");
    VirtualAllocEx = def(PFN_VirtualAllocEx, "VirtualAllocEx", "kernel32");
    VirtualProtectEx = def(PFN_VirtualProtectEx, "VirtualProtectEx", "kernel32");
    CreateFileMappingA = def(PFN_CreateFileMappingA, "CreateFileMappingA", "kernel32");
    GetThreadContext = def(PFN_GetThreadContext, "GetThreadContext", "kernel32");
    GetThreadId = def(PFN_GetThreadId, "GetThreadId", "kernel32");
    SetThreadContext = def(PFN_SetThreadContext, "SetThreadContext", "kernel32");
    MapViewOfFile = def(PFN_MapViewOfFile, "MapViewOfFile", "kernel32");
    UnmapViewOfFile = def(PFN_UnmapViewOfFile, "UnmapViewOfFile", "kernel32");
    OpenProcess = def(PFN_OpenProcess, "OpenProcess", "kernel32");
    OpenThread = def(PFN_OpenThread, "OpenThread", "kernel32");
    WriteProcessMemory = def(PFN_WriteProcessMemory, "WriteProcessMemory", "kernel32");
    ReadProcessMemory = def(PFN_ReadProcessMemory, "ReadProcessMemory", "kernel32");
    CreateRemoteThread = def(PFN_CreateRemoteThread, "CreateRemoteThread", "kernel32");
    GetCurrentDirectoryW = def(PFN_GetCurrentDirectoryW, "GetCurrentDirectoryW", "kernel32");
    HeapAlloc = def(PFN_HeapAlloc, "HeapAlloc", "kernel32");
    HeapFree = def(PFN_HeapFree, "HeapFree", "kernel32");
    GetProcessHeap = def(PFN_GetProcessHeap, "GetProcessHeap", "kernel32");
    GetFileSizeEx = def(PFN_GetFileSizeEx, "GetFileSizeEx", "kernel32");
    SetFilePointerEx = def(PFN_SetFilePointerEx, "SetFilePointerEx", "kernel32");
    LocalFree = def(PFN_LocalFree, "LocalFree", "kernel32");

    NtResumeThread = def(PFN_NtResumeThread, "NtResumeThread", "ntdll");
    NtSuspendThread = def(PFN_NtSuspendThread, "NtSuspendThread", "ntdll");
    NtTerminateThread = def(PFN_NtTerminateThread, "NtTerminateThread", "ntdll");
    NtTerminateProcess = def(PFN_NtTerminateProcess, "NtTerminateProcess", "ntdll");
    NtResumeProcess = def(PFN_NtResumeProcess, "NtResumeProcess", "ntdll");
    NtSuspendProcess = def(PFN_NtSuspendProcess, "NtSuspendProcess", "ntdll");
    NtCreateJobObject = def(PFN_NtCreateJobObject, "NtCreateJobObject", "ntdll");
    NtAssignProcessToJobObject = def(PFN_NtAssignProcessToJobObject, "NtAssignProcessToJobObject", "ntdll");
    NtTerminateJobObject = def(PFN_NtTerminateJobObject, "NtTerminateJobObject", "ntdll");
    NtIsProcessInJob = def(PFN_NtIsProcessInJob, "NtIsProcessInJob", "ntdll");
    NtSetInformationJobObject = def(PFN_NtSetInformationJobObject, "NtSetInformationJobObject", "ntdll");
    NtClose = def(PFN_NtClose, "NtClose", "ntdll");
    NtWriteVirtualMemory = def(PFN_NtWriteVirtualMemory, "NtWriteVirtualMemory", "ntdll");
    NtProtectVirtualMemory = def(PFN_NtProtectVirtualMemory, "NtProtectVirtualMemory", "ntdll");
    NtCreateThreadEx = def(PFN_NtCreateThreadEx, "NtCreateThreadEx", "ntdll");
    NtCreateUserProcess = def(PFN_NtCreateUserProcess, "NtCreateUserProcess", "ntdll");
    RtlCloneUserProcess = def(PFN_RtlCloneUserProcess, "RtlCloneUserProcess", "ntdll");
    RtlWow64EnableFsRedirection = def(PFN_RtlWow64EnableFsRedirection, "RtlWow64EnableFsRedirection", "ntdll");
    NtCreateNamedPipeFile = def(PFN_NtCreateNamedPipeFile, "NtCreateNamedPipeFile", "ntdll");
    RtlSetCurrentDirectory_U = def(PFN_RtlSetCurrentDirectory_U, "RtlSetCurrentDirectory_U", "ntdll");
    RtlGetSystemTimePrecise = def(PFN_RtlGetSystemTimePrecise, "RtlGetSystemTimePrecise", "ntdll");
    RtlGetFullPathName_U = def(PFN_RtlGetFullPathName_U, "RtlGetFullPathName_U", "ntdll");
    NtQueryObject = def(PFN_NtQueryObject, "NtQueryObject", "ntdll");

    MessageBoxA = def(PFN_MessageBoxA, "MessageBoxA", "user32");
    MessageBoxW = def(PFN_MessageBoxW, "MessageBoxW", "user32");
    EnumWindows = def(PFN_EnumWindows, "EnumWindows", "user32");
    GetWindowThreadProcessId = def(PFN_GetWindowThreadProcessId, "GetWindowThreadProcessId", "user32");
    SetForegroundWindow = def(PFN_SetForegroundWindow, "SetForegroundWindow", "user32");
    GetForegroundWindow = def(PFN_GetForegroundWindow, "GetForegroundWindow", "user32");

    CoInitializeEx = def(PFN_CoInitializeEx, "CoInitializeEx", "ole32");
    CoUninitialize = def(PFN_CoUninitialize, "CoUninitialize", "ole32");
    CoTaskMemAlloc = def(PFN_CoTaskMemAlloc, "CoTaskMemAlloc", "ole32");
    CoTaskMemFree = def(PFN_CoTaskMemFree, "CoTaskMemFree", "ole32");
    CoGetCurrentProcess = def(PFN_CoGetCurrentProcess, "CoGetCurrentProcess", "ole32");
    CoGetCallerTID = def(PFN_CoGetCallerTID, "CoGetCallerTID", "ole32");

    OpenProcessToken = def(PFN_OpenProcessToken, "OpenProcessToken", "advapi32");
    GetTokenInformation = def(PFN_GetTokenInformation, "GetTokenInformation", "advapi32");
    CheckTokenMembership = def(PFN_CheckTokenMembership, "CheckTokenMembership", "advapi32");
    AllocateAndInitializeSid = def(PFN_AllocateAndInitializeSid, "AllocateAndInitializeSid", "advapi32");
    FreeSid = def(PFN_FreeSid, "FreeSid", "advapi32");
    ConvertSidToStringSidA = def(PFN_ConvertSidToStringSidA, "ConvertSidToStringSidA", "advapi32");
    RtlGenRandom = def(PFN_RtlGenRandom, "SystemFunction036", "advapi32");

    WSAStartup = def(PFN_WSAStartup, "WSAStartup", "ws2_32");
    WSACleanup = def(PFN_WSACleanup, "WSACleanup", "ws2_32");
    WSAGetLastError = def(PFN_WSAGetLastError, "WSAGetLastError", "ws2_32");
    WSASocketW = def(PFN_WSASocketW, "WSASocketW", "ws2_32");
    WSAPoll = def(PFN_WSAPoll, "WSAPoll", "ws2_32");
    WSAGetOverlappedResult = def(PFN_WSAGetOverlappedResult, "WSAGetOverlappedResult", "ws2_32");
    WSASend = def(PFN_WSASend, "WSASend", "ws2_32");
    WSASendTo = def(PFN_WSASendTo, "WSASendTo", "ws2_32");
    WSARecvFrom = def(PFN_WSARecvFrom, "WSARecvFrom", "ws2_32");
    closesocket = def(PFN_closesocket, "closesocket", "ws2_32");
    getaddrinfo = def(PFN_getaddrinfo, "getaddrinfo", "ws2_32");
    freeaddrinfo = def(PFN_freeaddrinfo, "freeaddrinfo", "ws2_32");
    bind = def(PFN_bind, "bind", "ws2_32");
    connect = def(PFN_connect, "connect", "ws2_32");
    ioctlsocket = def(PFN_ioctlsocket, "ioctlsocket", "ws2_32");
    getsockopt = def(PFN_getsockopt, "getsockopt", "ws2_32");
    setsockopt = def(PFN_setsockopt, "setsockopt", "ws2_32");

    GetUserNameExA = def(PFN_GetUserNameExA, "GetUserNameExA", "secur32");
}

//
// KERNEL32 function definitions
//
pub var GetCurrentThreadId: PFN_GetCurrentThreadId = undefined;
pub var FreeLibrary: PFN_FreeLibrary = undefined;
pub var CreateThread: PFN_CreateThread = undefined;
pub var GetSystemInfo: PFN_GetSystemInfo = undefined;
pub var VirtualFreeEx: PFN_VirtualFreeEx = undefined;
pub var WriteFile: PFN_WriteFile = undefined;
pub var DuplicateHandle: PFN_DuplicateHandle = undefined;
pub var ReadFile: PFN_ReadFile = undefined;
pub var GetModuleFileNameA: PFN_GetModuleFileNameA = undefined;
pub var GetCurrentProcessId: PFN_GetCurrentProcessId = undefined;
pub var GetProcessId: PFN_GetProcessId = undefined;
pub var GetCurrentThread: PFN_GetCurrentThread = undefined;
pub var CloseHandle: PFN_CloseHandle = undefined;
pub var FlushInstructionCache: PFN_FlushInstructionCache = undefined;
pub var FreeConsole: PFN_FreeConsole = undefined;
pub var AttachConsole: PFN_AttachConsole = undefined;
pub var IsWow64Process: PFN_IsWow64Process = undefined;
pub var GetExitCodeProcess: PFN_GetExitCodeProcess = undefined;
pub var GetModuleHandleA: PFN_GetModuleHandleA = undefined;
pub var LoadLibraryA: PFN_LoadLibraryA = undefined;
pub var GetProcAddress: PFN_GetProcAddress = undefined;
pub var CreatePipe: PFN_CreatePipe = undefined;
pub var ResumeThread: PFN_ResumeThread = undefined;
pub var SuspendThread: PFN_ResumeThread = undefined;
pub var VirtualAllocEx: PFN_VirtualAllocEx = undefined;
pub var VirtualProtectEx: PFN_VirtualProtectEx = undefined;
pub var CreateFileMappingA: PFN_CreateFileMappingA = undefined;
pub var GetThreadContext: PFN_GetThreadContext = undefined;
pub var GetThreadId: PFN_GetThreadId = undefined;
pub var SetThreadContext: PFN_SetThreadContext = undefined;
pub var MapViewOfFile: PFN_MapViewOfFile = undefined;
pub var UnmapViewOfFile: PFN_UnmapViewOfFile = undefined;
pub var OpenProcess: PFN_OpenProcess = undefined;
pub var OpenThread: PFN_OpenThread = undefined;
pub var WriteProcessMemory: PFN_WriteProcessMemory = undefined;
pub var ReadProcessMemory: PFN_ReadProcessMemory = undefined;
pub var CreateRemoteThread: PFN_CreateRemoteThread = undefined;
pub var GetCurrentDirectoryW: PFN_GetCurrentDirectoryW = undefined;
pub var HeapAlloc: PFN_HeapAlloc = undefined;
pub var HeapFree: PFN_HeapFree = undefined;
pub var GetProcessHeap: PFN_GetProcessHeap = undefined;
pub var GetFileSizeEx: PFN_GetFileSizeEx = undefined;
pub var SetFilePointerEx: PFN_SetFilePointerEx = undefined;
pub var LocalFree: PFN_LocalFree = undefined;

//
// NTDLL function definitions
//
pub var NtResumeThread: PFN_NtResumeThread = undefined;
pub var NtSuspendThread: PFN_NtSuspendThread = undefined;
pub var NtTerminateThread: PFN_NtTerminateThread = undefined;
pub var NtTerminateProcess: PFN_NtTerminateProcess = undefined;
pub var NtResumeProcess: PFN_NtResumeProcess = undefined;
pub var NtSuspendProcess: PFN_NtSuspendProcess = undefined;
pub var NtCreateJobObject: PFN_NtCreateJobObject = undefined;
pub var NtAssignProcessToJobObject: PFN_NtAssignProcessToJobObject = undefined;
pub var NtTerminateJobObject: PFN_NtTerminateJobObject = undefined;
pub var NtIsProcessInJob: PFN_NtIsProcessInJob = undefined;
pub var NtSetInformationJobObject: PFN_NtSetInformationJobObject = undefined;
pub var NtClose: PFN_NtClose = undefined;
pub var NtWriteVirtualMemory: PFN_NtWriteVirtualMemory = undefined;
pub var NtProtectVirtualMemory: PFN_NtProtectVirtualMemory = undefined;
pub var NtCreateThreadEx: PFN_NtCreateThreadEx = undefined;
pub var NtCreateUserProcess: PFN_NtCreateUserProcess = undefined;
pub var RtlCloneUserProcess: PFN_RtlCloneUserProcess = undefined;
pub var RtlWow64EnableFsRedirection: PFN_RtlWow64EnableFsRedirection = undefined;
pub var NtCreateNamedPipeFile: PFN_NtCreateNamedPipeFile = undefined;
pub var RtlSetCurrentDirectory_U: PFN_RtlSetCurrentDirectory_U = undefined;
pub var RtlGetSystemTimePrecise: PFN_RtlGetSystemTimePrecise = undefined;
pub var RtlGetFullPathName_U: PFN_RtlGetFullPathName_U = undefined;
pub var NtQueryObject: PFN_NtQueryObject = undefined;

pub fn NtCurrentProcess() HANDLE {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
}
pub fn NtCurrentThread() HANDLE {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, -2))));
}
pub fn NtCurrentSession() HANDLE {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, -3))));
}

//
// USER32 function definitions
//
pub var MessageBoxA: PFN_MessageBoxA = undefined;
pub var MessageBoxW: PFN_MessageBoxW = undefined;
pub var EnumWindows: PFN_EnumWindows = undefined;
pub var GetWindowThreadProcessId: PFN_GetWindowThreadProcessId = undefined;
pub var SetForegroundWindow: PFN_SetForegroundWindow = undefined;
pub var GetForegroundWindow: PFN_GetForegroundWindow = undefined;

//
// OLE32 function definitions
//
pub var CoInitializeEx: PFN_CoInitializeEx = undefined;
pub var CoUninitialize: PFN_CoUninitialize = undefined;
pub var CoTaskMemAlloc: PFN_CoTaskMemAlloc = undefined;
pub var CoTaskMemFree: PFN_CoTaskMemFree = undefined;
pub var CoGetCurrentProcess: PFN_CoGetCurrentProcess = undefined;
pub var CoGetCallerTID: PFN_CoGetCallerTID = undefined;

//
// ADVAPI32 function definitions
//
pub var OpenProcessToken: PFN_OpenProcessToken = undefined;
pub var GetTokenInformation: PFN_GetTokenInformation = undefined;
pub var CheckTokenMembership: PFN_CheckTokenMembership = undefined;
pub var AllocateAndInitializeSid: PFN_AllocateAndInitializeSid = undefined;
pub var FreeSid: PFN_FreeSid = undefined;
pub var ConvertSidToStringSidA: PFN_ConvertSidToStringSidA = undefined;
pub var RtlGenRandom: PFN_RtlGenRandom = undefined;

//
// WS2_32 function definitions
//
pub var WSAStartup: PFN_WSAStartup = undefined;
pub var WSACleanup: PFN_WSACleanup = undefined;
pub var WSAGetLastError: PFN_WSAGetLastError = undefined;
pub var WSASocketW: PFN_WSASocketW = undefined;
pub var WSAPoll: PFN_WSAPoll = undefined;
pub var WSAGetOverlappedResult: PFN_WSAGetOverlappedResult = undefined;
pub var WSASend: PFN_WSASend = undefined;
pub var WSASendTo: PFN_WSASendTo = undefined;
pub var WSARecv: PFN_WSARecv = undefined;
pub var WSARecvFrom: PFN_WSARecvFrom = undefined;
pub var closesocket: PFN_closesocket = undefined;
pub var getaddrinfo: PFN_getaddrinfo = undefined;
pub var freeaddrinfo: PFN_freeaddrinfo = undefined;
pub var bind: PFN_bind = undefined;
pub var connect: PFN_connect = undefined;
pub var ioctlsocket: PFN_ioctlsocket = undefined;
pub var getsockopt: PFN_getsockopt = undefined;
pub var setsockopt: PFN_setsockopt = undefined;

//
// SECUR_32 function definitions
//
pub var GetUserNameExA: PFN_GetUserNameExA = undefined;

//
// "Redirectors"
// Transform "call FuncName" to "call [__imp_FuncName]", in other words enable __declspec(dllimport).
// This is necessary because Zig's libstd does not use __declspec(dllimport).
//
comptime {
    if (@import("builtin").mode != .Debug and @import("builtin").os.tag == .windows and bof) {
        @export(&NtAllocateVirtualMemory, .{ .name = "NtAllocateVirtualMemory", .linkage = .strong });
        @export(&NtFreeVirtualMemory, .{ .name = "NtFreeVirtualMemory", .linkage = .strong });
        @export(&NtDeviceIoControlFile, .{ .name = "NtDeviceIoControlFile", .linkage = .strong });
        @export(&NtFsControlFile, .{ .name = "NtFsControlFile", .linkage = .strong });
        @export(&NtLockFile, .{ .name = "NtLockFile", .linkage = .strong });
        @export(&NtUnlockFile, .{ .name = "NtUnlockFile", .linkage = .strong });
        @export(&NtQueryDirectoryFile, .{ .name = "NtQueryDirectoryFile", .linkage = .strong });
        @export(&NtQueryInformationFile, .{ .name = "NtQueryInformationFile", .linkage = .strong });
        @export(&NtQueryVolumeInformationFile, .{ .name = "NtQueryVolumeInformationFile", .linkage = .strong });
        @export(&NtQueryAttributesFile, .{ .name = "NtQueryAttributesFile", .linkage = .strong });
        @export(&NtSetInformationFile, .{ .name = "NtSetInformationFile", .linkage = .strong });
        @export(&NtReadFile, .{ .name = "NtReadFile", .linkage = .strong });
        @export(&NtWriteFile, .{ .name = "NtWriteFile", .linkage = .strong });
    }
}

pub fn NtAllocateVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: *PVOID,
    ZeroBits: ULONG_PTR,
    RegionSize: *SIZE_T,
    AllocationType: DWORD,
    Protect: DWORD,
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtAllocateVirtualMemory), "NtAllocateVirtualMemory", "ntdll");
    return f(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

pub fn NtFreeVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: *PVOID,
    RegionSize: *SIZE_T,
    FreeType: DWORD,
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtFreeVirtualMemory), "NtFreeVirtualMemory", "ntdll");
    return f(ProcessHandle, BaseAddress, RegionSize, FreeType);
}
