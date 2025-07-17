const std = @import("std");
const windows = std.os.windows;

pub const ATTACH_PARENT_PROCESS = 0xffff_ffff;

pub const OVERLAPPED = windows.OVERLAPPED;
pub const Win32Error = windows.Win32Error;
pub const ULONG = windows.ULONG;
pub const WCHAR = windows.WCHAR;
pub const LPCSTR = windows.LPCSTR;
pub const LPSTR = windows.LPSTR;
pub const WINAPI = windows.WINAPI;
pub const HMODULE = windows.HMODULE;
pub const HINSTANCE = windows.HINSTANCE;
pub const FARPROC = windows.FARPROC;
pub const HANDLE = windows.HANDLE;
pub const WORD = windows.WORD;
pub const DWORD = windows.DWORD;
pub const BOOL = windows.BOOL;
pub const TRUE = windows.TRUE;
pub const FALSE = windows.FALSE;
pub const OSVERSIONINFOW = windows.OSVERSIONINFOW;
pub const RTL_OSVERSIONINFOW = windows.RTL_OSVERSIONINFOW;
pub const PVOID = windows.PVOID;
pub const LPVOID = windows.LPVOID;
pub const PSECURITY_DESCRIPTOR = PVOID;
pub const NTSTATUS = windows.NTSTATUS;
pub const CLIENT_ID = extern struct {
    UniqueProcess: ?HANDLE,
    UniqueThread: ?HANDLE,
};
pub const UNICODE_STRING = windows.UNICODE_STRING;
pub const USHORT = windows.USHORT;
pub const BOOLEAN = windows.BOOLEAN;
pub const SIZE_T = windows.SIZE_T;
pub const UCHAR = windows.UCHAR;
pub const HRESULT = windows.HRESULT;
pub const ACCESS_MASK = windows.ACCESS_MASK;
pub const LARGE_INTEGER = windows.LARGE_INTEGER;
pub const ULONG_PTR = windows.ULONG_PTR;
pub const ULONGLONG = windows.ULONGLONG;
pub const LPCVOID = windows.LPCVOID;
pub const HWND = windows.HWND;
pub const UINT = windows.UINT;
pub const CONTEXT = windows.CONTEXT;
pub const LPTHREAD_START_ROUTINE = windows.LPTHREAD_START_ROUTINE;
pub const PMEMORY_BASIC_INFORMATION = windows.PMEMORY_BASIC_INFORMATION;
pub const SYSTEM_INFO = windows.SYSTEM_INFO;
pub const LPARAM = windows.LPARAM;
pub const WNDENUMPROC = *const fn (HWND, LPARAM) callconv(.winapi) BOOL;
pub const FILE_BOTH_DIR_INFORMATION = windows.FILE_BOTH_DIR_INFORMATION;
pub const FILE_BOTH_DIRECTORY_INFORMATION = windows.FILE_BOTH_DIRECTORY_INFORMATION;
pub const WinsockError = windows.ws2_32.WinsockError;
pub const WSAPROTOCOL_INFOW = windows.ws2_32.WSAPROTOCOL_INFOW;
pub const SOCKET = windows.ws2_32.SOCKET;
pub const addrinfo = windows.ws2_32.addrinfo;
pub const addrinfoa = windows.ws2_32.addrinfoa;
pub const sockaddr = windows.ws2_32.sockaddr;
pub const WSABUF = windows.ws2_32.WSABUF;
pub const LPWSAOVERLAPPED_COMPLETION_ROUTINE = windows.ws2_32.LPWSAOVERLAPPED_COMPLETION_ROUTINE;
pub const WSAPOLLFD = windows.ws2_32.WSAPOLLFD;
pub const IO_STATUS_BLOCK = windows.IO_STATUS_BLOCK;
pub const IO_APC_ROUTINE = windows.IO_APC_ROUTINE;
pub const FILE_INFORMATION_CLASS = windows.FILE_INFORMATION_CLASS;
pub const OBJECT_INFORMATION_CLASS = windows.OBJECT_INFORMATION_CLASS;

pub const INFINITE = windows.INFINITE;
pub const WAIT_FAILED = windows.WAIT_FAILED;

pub const MEM_COMMIT = windows.MEM_COMMIT;
pub const MEM_RESERVE = windows.MEM_RESERVE;
pub const MEM_FREE = windows.MEM_FREE;
pub const MEM_RESET = windows.MEM_RESET;
pub const MEM_RESET_UNDO = windows.MEM_RESET_UNDO;
pub const MEM_LARGE_PAGES = windows.MEM_LARGE_PAGES;
pub const MEM_PHYSICAL = windows.MEM_PHYSICAL;
pub const MEM_TOP_DOWN = windows.MEM_TOP_DOWN;
pub const MEM_WRITE_WATCH = windows.MEM_WRITE_WATCH;
pub const MEM_COALESCE_PLACEHOLDERS = windows.MEM_COALESCE_PLACEHOLDERS;
pub const MEM_RESERVE_PLACEHOLDERS = windows.MEM_RESERVE_PLACEHOLDERS;
pub const MEM_DECOMMIT = windows.MEM_DECOMMIT;
pub const MEM_RELEASE = windows.MEM_RELEASE;

pub const PAGE_EXECUTE = windows.PAGE_EXECUTE;
pub const PAGE_EXECUTE_READ = windows.PAGE_EXECUTE_READ;
pub const PAGE_EXECUTE_READWRITE = windows.PAGE_EXECUTE_READWRITE;
pub const PAGE_EXECUTE_WRITECOPY = windows.PAGE_EXECUTE_WRITECOPY;
pub const PAGE_NOACCESS = windows.PAGE_NOACCESS;
pub const PAGE_READONLY = windows.PAGE_READONLY;
pub const PAGE_READWRITE = windows.PAGE_READWRITE;
pub const PAGE_WRITECOPY = windows.PAGE_WRITECOPY;
pub const PAGE_TARGETS_INVALID = windows.PAGE_TARGETS_INVALID;
pub const PAGE_TARGETS_NO_UPDATE = windows.PAGE_TARGETS_NO_UPDATE;
pub const PAGE_GUARD = windows.PAGE_GUARD;
pub const PAGE_NOCACHE = windows.PAGE_NOCACHE;
pub const PAGE_WRITECOMBINE = windows.PAGE_WRITECOMBINE;

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

pub const THREADINFOCLASS = windows.THREADINFOCLASS;
pub const PROCESSINFOCLASS = windows.PROCESSINFOCLASS;
pub const PROCESS_BASIC_INFORMATION = windows.PROCESS_BASIC_INFORMATION;
pub const SECURITY_ATTRIBUTES = windows.SECURITY_ATTRIBUTES;
pub const SYSTEM_INFORMATION_CLASS = windows.SYSTEM_INFORMATION_CLASS;
pub const SYSTEM_BASIC_INFORMATION = windows.SYSTEM_BASIC_INFORMATION;

pub const WSADATA = windows.ws2_32.WSADATA;
pub const AF = windows.ws2_32.AF;
pub const SOCK = windows.ws2_32.SOCK;

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

pub const OBJ_INHERIT = windows.OBJ_INHERIT;
pub const OBJ_PERMANENT = windows.OBJ_PERMANENT;
pub const OBJ_EXCLUSIVE = windows.OBJ_EXCLUSIVE;
pub const OBJ_CASE_INSENSITIVE = windows.OBJ_CASE_INSENSITIVE;
pub const OBJ_OPENIF = windows.OBJ_OPENIF;
pub const OBJ_OPENLINK = windows.OBJ_OPENLINK;
pub const OBJ_KERNEL_HANDLE = windows.OBJ_KERNEL_HANDLE;
pub const OBJ_VALID_ATTRIBUTES = windows.OBJ_VALID_ATTRIBUTES;

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

//
// KERNEL32 function types
//
pub const PFN_VirtualAlloc = *const fn (
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    flAllocationType: DWORD,
    flProtect: DWORD,
) callconv(.winapi) ?LPVOID;

pub const PFN_VirtualQuery = *const fn (
    lpAddress: ?LPVOID,
    lpBuffer: PMEMORY_BASIC_INFORMATION,
    dwLength: SIZE_T,
) callconv(.winapi) SIZE_T;

pub const PFN_VirtualProtect = *const fn (
    lpAddress: LPVOID,
    dwSize: SIZE_T,
    flNewProtect: DWORD,
    lpflOldProtect: *DWORD,
) callconv(.winapi) BOOL;

pub const PFN_VirtualFree = *const fn (
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    dwFreeType: DWORD,
) callconv(.winapi) BOOL;

pub const PFN_GetLastError = *const fn () callconv(.winapi) Win32Error;

pub const PFN_Sleep = *const fn (dwMilliseconds: DWORD) callconv(.winapi) void;

pub const PFN_ExitProcess = *const fn (uExitCode: UINT) callconv(.winapi) void;

pub const PFN_GetCurrentProcess = *const fn () callconv(.winapi) HANDLE;

pub const PFN_WaitForSingleObject = *const fn (
    hHandle: HANDLE,
    dwMilliseconds: DWORD,
) callconv(.winapi) DWORD;

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

//
// NTDLL function types
//
pub const PFN_RtlGetVersion = *const fn (lpVersionInformation: *RTL_OSVERSIONINFOW) callconv(.winapi) NTSTATUS;

pub const PFN_RtlCloneUserProcess = *const fn (
    ProcessFlags: ULONG,
    ProcessSecurityDescriptor: ?PSECURITY_DESCRIPTOR,
    ThreadSecurityDescriptor: ?PSECURITY_DESCRIPTOR,
    DebugPort: ?HANDLE,
    ProcessInformation: *RTL_USER_PROCESS_INFORMATION,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtResumeThread = *const fn (
    ThreadHandle: HANDLE,
    PreviousSuspendCount: ?*ULONG,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtSuspendThread = *const fn (
    ThreadHandle: HANDLE,
    PreviousSuspendCount: ?*ULONG,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtTerminateThread = *const fn (
    ThreadHandle: ?HANDLE,
    ExitStatus: NTSTATUS,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtTerminateProcess = *const fn (
    ProcessHandle: ?HANDLE,
    ExitStatus: NTSTATUS,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtOpenProcess = *const fn (
    ProcessHandle: *HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: *OBJECT_ATTRIBUTES,
    ClientId: ?*CLIENT_ID,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtResumeProcess = *const fn (ProcessHandle: HANDLE) callconv(.winapi) NTSTATUS;

pub const PFN_NtSuspendProcess = *const fn (ProcessHandle: HANDLE) callconv(.winapi) NTSTATUS;

pub const PFN_NtCreateJobObject = *const fn (
    JobHandle: *HANDLE,
    DesiredAccess: ACCESS_MASK,
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

pub const PFN_NtClose = *const fn (hHandle: HANDLE) callconv(.winapi) NTSTATUS;

pub const PFN_RtlWow64EnableFsRedirection = *const fn (Wow64FsEnableRedirection: BOOLEAN) callconv(.winapi) NTSTATUS;

pub const PFN_NtAllocateVirtualMemory = *const fn (
    ProcessHandle: HANDLE,
    BaseAddress: *PVOID,
    ZeroBits: ULONG_PTR,
    RegionSize: *SIZE_T,
    AllocationType: ULONG,
    Protect: ULONG,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtWriteVirtualMemory = *const fn (
    ProcessHandle: HANDLE,
    BaseAddress: ?PVOID,
    Buffer: LPCVOID,
    NumberOfBytesToWrite: SIZE_T,
    NumberOfBytesWritten: ?*SIZE_T,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtProtectVirtualMemory = *const fn (
    ProcessHandle: HANDLE,
    BaseAddress: *?PVOID,
    NumberOfBytesToProtect: *SIZE_T,
    NewAccessProtection: ULONG,
    OldAccessProtection: *ULONG,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtCreateThreadEx = *const fn (
    ThreadHandle: *HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: ?*OBJECT_ATTRIBUTES,
    ProcessHandle: HANDLE,
    StartRoutine: PVOID,
    Argument: ?PVOID,
    CreateFlags: ULONG,
    ZeroBits: SIZE_T,
    StackSize: SIZE_T,
    MaximumStackSize: SIZE_T,
    AttributeList: ?*anyopaque, // TODO: ?*PS_ATTRIBUTE_LIST,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtCreateUserProcess = *const fn (
    ProcessHandle: *HANDLE,
    ThreadHandle: *HANDLE,
    ProcessDesiredAccess: ACCESS_MASK,
    ThreadDesiredAccess: ACCESS_MASK,
    ProcessObjectAttributes: ?*OBJECT_ATTRIBUTES,
    ThreadObjectAttributes: ?*OBJECT_ATTRIBUTES,
    ProcessFlags: ULONG,
    ThreadFlags: ULONG,
    ProcessParameters: ?PVOID,
    CreateInfo: *PS_CREATE_INFO,
    AttributeList: ?*anyopaque, // TODO: ?*PS_ATTRIBUTE_LIST,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtCreateFile = *const fn (
    FileHandle: *HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: *OBJECT_ATTRIBUTES,
    IoStatusBlock: *IO_STATUS_BLOCK,
    AllocationSize: ?*LARGE_INTEGER,
    FileAttributes: ULONG,
    ShareAccess: ULONG,
    CreateDisposition: ULONG,
    CreateOptions: ULONG,
    EaBuffer: ?*anyopaque,
    EaLength: ULONG,
) callconv(.winapi) NTSTATUS;

pub const PFN_RtlSetCurrentDirectory_U = *const fn (PathName: *UNICODE_STRING) callconv(.winapi) NTSTATUS;

pub const PFN_RtlGetSystemTimePrecise = *const fn () callconv(.winapi) LARGE_INTEGER;

pub const PFN_RtlGetFullPathName_U = *const fn (
    FileName: [*:0]const u16,
    BufferByteLength: ULONG,
    Buffer: [*]u16,
    ShortName: ?*[*:0]const u16,
) callconv(.winapi) ULONG;

pub const PFN_NtQueryDirectoryFile = *const fn (
    FileHandle: HANDLE,
    Event: ?HANDLE,
    ApcRoutine: ?IO_APC_ROUTINE,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *IO_STATUS_BLOCK,
    FileInformation: *anyopaque,
    Length: ULONG,
    FileInformationClass: FILE_INFORMATION_CLASS,
    ReturnSingleEntry: BOOLEAN,
    FileName: ?*UNICODE_STRING,
    RestartScan: BOOLEAN,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtQueryObject = *const fn (
    Handle: HANDLE,
    ObjectInformationClass: OBJECT_INFORMATION_CLASS,
    ObjectInformation: PVOID,
    ObjectInformationLength: ULONG,
    ReturnLength: ?*ULONG,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtLockFile = *const fn (
    FileHandle: HANDLE,
    Event: ?HANDLE,
    ApcRoutine: ?*IO_APC_ROUTINE,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *IO_STATUS_BLOCK,
    ByteOffset: *const LARGE_INTEGER,
    Length: *const LARGE_INTEGER,
    Key: ?*ULONG,
    FailImmediately: BOOLEAN,
    ExclusiveLock: BOOLEAN,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtDeviceIoControlFile = *const fn (
    FileHandle: HANDLE,
    Event: ?HANDLE,
    ApcRoutine: ?IO_APC_ROUTINE,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *IO_STATUS_BLOCK,
    IoControlCode: ULONG,
    InputBuffer: ?*const anyopaque,
    InputBufferLength: ULONG,
    OutputBuffer: ?PVOID,
    OutputBufferLength: ULONG,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtFsControlFile = *const fn (
    FileHandle: HANDLE,
    Event: ?HANDLE,
    ApcRoutine: ?IO_APC_ROUTINE,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *IO_STATUS_BLOCK,
    FsControlCode: ULONG,
    InputBuffer: ?*const anyopaque,
    InputBufferLength: ULONG,
    OutputBuffer: ?PVOID,
    OutputBufferLength: ULONG,
) callconv(.winapi) NTSTATUS;

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

//
// USER32 function types
//
pub const PFN_MessageBoxA = *const fn (
    hWnd: ?HWND,
    lpText: ?LPCSTR,
    lpCaption: ?LPCSTR,
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

pub const PFN_WSAGetLastError = *const fn () callconv(.winapi) i32;

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
// Define WIN32 function
//
pub const bof = @import("options").bof;

pub fn def(
    comptime T: type,
    comptime funcname: []const u8,
    comptime libname: []const u8,
) if (@import("options").define_functions) T else void {
    return if (@import("options").define_functions)
        @extern(T, .{
            .name = if (bof) libname ++ "$" ++ funcname else funcname,
            .is_dll_import = true,
        })
    else {};
}

//
// KERNEL32 function definitions
//
pub const VirtualAlloc = def(?PFN_VirtualAlloc, "VirtualAlloc", "kernel32");
pub const VirtualQuery = def(?PFN_VirtualQuery, "VirtualQuery", "kernel32");
pub const VirtualProtect = def(?PFN_VirtualProtect, "VirtualProtect", "kernel32");
pub const VirtualFree = def(?PFN_VirtualFree, "VirtualFree", "kernel32");
pub const GetLastError = def(?PFN_GetLastError, "GetLastError", "kernel32");
pub const Sleep = def(?PFN_Sleep, "Sleep", "kernel32");
pub const ExitProcess = def(?PFN_ExitProcess, "ExitProcess", "kernel32");
pub const GetCurrentProcess = def(?PFN_GetCurrentProcess, "GetCurrentProcess", "kernel32");
pub const GetCurrentThreadId = def(?PFN_GetCurrentThreadId, "GetCurrentThreadId", "kernel32");
pub const FreeLibrary = def(?PFN_FreeLibrary, "FreeLibrary", "kernel32");
pub const CreateThread = def(?PFN_CreateThread, "CreateThread", "kernel32");
pub const GetSystemInfo = def(?PFN_GetSystemInfo, "GetSystemInfo", "kernel32");
pub const VirtualFreeEx = def(?PFN_VirtualFreeEx, "VirtualFreeEx", "kernel32");
pub const WriteFile = def(?PFN_WriteFile, "WriteFile", "kernel32");
pub const DuplicateHandle = def(?PFN_DuplicateHandle, "DuplicateHandle", "kernel32");
pub const ReadFile = def(?PFN_ReadFile, "ReadFile", "kernel32");
pub const WaitForSingleObject = def(?PFN_WaitForSingleObject, "WaitForSingleObject", "kernel32");
pub const GetModuleFileNameA = def(?PFN_GetModuleFileNameA, "GetModuleFileNameA", "kernel32");
pub const GetCurrentProcessId = def(?PFN_GetCurrentProcessId, "GetCurrentProcessId", "kernel32");
pub const GetProcessId = def(?PFN_GetProcessId, "GetProcessId", "kernel32");
pub const GetCurrentThread = def(?PFN_GetCurrentThread, "GetCurrentThread", "kernel32");
pub const CloseHandle = def(?PFN_CloseHandle, "CloseHandle", "kernel32");
pub const FlushInstructionCache = def(?PFN_FlushInstructionCache, "FlushInstructionCache", "kernel32");
pub const FreeConsole = def(?PFN_FreeConsole, "FreeConsole", "kernel32");
pub const AttachConsole = def(?PFN_AttachConsole, "AttachConsole", "kernel32");
pub const IsWow64Process = def(?PFN_IsWow64Process, "IsWow64Process", "kernel32");
pub const GetExitCodeProcess = def(?PFN_GetExitCodeProcess, "GetExitCodeProcess", "kernel32");
pub const GetModuleHandleA = def(?PFN_GetModuleHandleA, "GetModuleHandleA", "kernel32");
pub const LoadLibraryA = def(?PFN_LoadLibraryA, "LoadLibraryA", "kernel32");
pub const GetProcAddress = def(?PFN_GetProcAddress, "GetProcAddress", "kernel32");
pub const CreatePipe = def(?PFN_CreatePipe, "CreatePipe", "kernel32");
pub const ResumeThread = def(?PFN_ResumeThread, "ResumeThread", "kernel32");
pub const VirtualAllocEx = def(?PFN_VirtualAllocEx, "VirtualAllocEx", "kernel32");
pub const VirtualProtectEx = def(?PFN_VirtualProtectEx, "VirtualProtectEx", "kernel32");
pub const CreateFileMappingA = def(?PFN_CreateFileMappingA, "CreateFileMappingA", "kernel32");
pub const GetThreadContext = def(?PFN_GetThreadContext, "GetThreadContext", "kernel32");
pub const GetThreadId = def(?PFN_GetThreadId, "GetThreadId", "kernel32");
pub const SetThreadContext = def(?PFN_SetThreadContext, "SetThreadContext", "kernel32");
pub const MapViewOfFile = def(?PFN_MapViewOfFile, "MapViewOfFile", "kernel32");
pub const UnmapViewOfFile = def(?PFN_UnmapViewOfFile, "UnmapViewOfFile", "kernel32");
pub const OpenProcess = def(?PFN_OpenProcess, "OpenProcess", "kernel32");
pub const OpenThread = def(?PFN_OpenThread, "OpenThread", "kernel32");
pub const WriteProcessMemory = def(?PFN_WriteProcessMemory, "WriteProcessMemory", "kernel32");
pub const ReadProcessMemory = def(?PFN_ReadProcessMemory, "ReadProcessMemory", "kernel32");
pub const CreateRemoteThread = def(?PFN_CreateRemoteThread, "CreateRemoteThread", "kernel32");
pub const GetCurrentDirectoryW = def(?PFN_GetCurrentDirectoryW, "GetCurrentDirectoryW", "kernel32");

//
// NTDLL function definitions
//
pub const NtResumeThread = def(?PFN_NtResumeThread, "NtResumeThread", "ntdll");
pub const NtSuspendThread = def(?PFN_NtSuspendThread, "NtSuspendThread", "ntdll");
pub const NtTerminateThread = def(?PFN_NtTerminateThread, "NtTerminateThread", "ntdll");
pub const NtTerminateProcess = def(?PFN_NtTerminateProcess, "NtTerminateProcess", "ntdll");
pub const NtOpenProcess = def(?PFN_NtOpenProcess, "NtOpenProcess", "ntdll");
pub const NtResumeProcess = def(?PFN_NtResumeProcess, "NtResumeProcess", "ntdll");
pub const NtSuspendProcess = def(?PFN_NtSuspendProcess, "NtSuspendProcess", "ntdll");
pub const NtCreateJobObject = def(?PFN_NtCreateJobObject, "NtCreateJobObject", "ntdll");
pub const NtAssignProcessToJobObject = def(?PFN_NtAssignProcessToJobObject, "NtAssignProcessToJobObject", "ntdll");
pub const NtTerminateJobObject = def(?PFN_NtTerminateJobObject, "NtTerminateJobObject", "ntdll");
pub const NtIsProcessInJob = def(?PFN_NtIsProcessInJob, "NtIsProcessInJob", "ntdll");
pub const NtSetInformationJobObject = def(?PFN_NtSetInformationJobObject, "NtSetInformationJobObject", "ntdll");
pub const NtClose = def(?PFN_NtClose, "NtClose", "ntdll");
pub const NtAllocateVirtualMemory = def(?PFN_NtAllocateVirtualMemory, "NtAllocateVirtualMemory", "ntdll");
pub const NtWriteVirtualMemory = def(?PFN_NtWriteVirtualMemory, "NtWriteVirtualMemory", "ntdll");
pub const NtProtectVirtualMemory = def(?PFN_NtProtectVirtualMemory, "NtProtectVirtualMemory", "ntdll");
pub const NtCreateThreadEx = def(?PFN_NtCreateThreadEx, "NtCreateThreadEx", "ntdll");
pub const NtCreateUserProcess = def(?PFN_NtCreateUserProcess, "NtCreateUserProcess", "ntdll");
pub const RtlGetVersion = def(?PFN_RtlGetVersion, "RtlGetVersion", "ntdll");
pub const RtlCloneUserProcess = def(?PFN_RtlCloneUserProcess, "RtlCloneUserProcess", "ntdll");
pub const RtlWow64EnableFsRedirection = def(?PFN_RtlWow64EnableFsRedirection, "RtlWow64EnableFsRedirection", "ntdll");
pub const NtCreateFile = def(?PFN_NtCreateFile, "NtCreateFile", "ntdll");
pub const RtlSetCurrentDirectory_U = def(?PFN_RtlSetCurrentDirectory_U, "RtlSetCurrentDirectory_U", "ntdll");
pub const RtlGetSystemTimePrecise = def(?PFN_RtlGetSystemTimePrecise, "RtlGetSystemTimePrecise", "ntdll");
pub const RtlGetFullPathName_U = def(?PFN_RtlGetFullPathName_U, "RtlGetFullPathName_U", "ntdll");
pub const NtQueryDirectoryFile = def(?PFN_NtQueryDirectoryFile, "NtQueryDirectoryFile", "ntdll");
pub const NtQueryObject = def(?PFN_NtQueryObject, "NtQueryObject", "ntdll");
pub const NtLockFile = def(?PFN_NtLockFile, "NtLockFile", "ntdll");
pub const NtDeviceIoControlFile = def(?PFN_NtDeviceIoControlFile, "NtDeviceIoControlFile", "ntdll");
pub const NtFsControlFile = def(?PFN_NtFsControlFile, "NtFsControlFile", "ntdll");

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
pub const MessageBoxA = def(?PFN_MessageBoxA, "MessageBoxA", "user32");
pub const EnumWindows = def(?PFN_EnumWindows, "EnumWindows", "user32");
pub const GetWindowThreadProcessId = def(?PFN_GetWindowThreadProcessId, "GetWindowThreadProcessId", "user32");
pub const SetForegroundWindow = def(?PFN_SetForegroundWindow, "SetForegroundWindow", "user32");
pub const GetForegroundWindow = def(?PFN_GetForegroundWindow, "GetForegroundWindow", "user32");

//
// OLE32 function definitions
//
pub const CoInitializeEx = def(?PFN_CoInitializeEx, "CoInitializeEx", "ole32");
pub const CoUninitialize = def(?PFN_CoUninitialize, "CoUninitialize", "ole32");
pub const CoTaskMemAlloc = def(?PFN_CoTaskMemAlloc, "CoTaskMemAlloc", "ole32");
pub const CoTaskMemFree = def(?PFN_CoTaskMemFree, "CoTaskMemFree", "ole32");
pub const CoGetCurrentProcess = def(?PFN_CoGetCurrentProcess, "CoGetCurrentProcess", "ole32");
pub const CoGetCallerTID = def(?PFN_CoGetCallerTID, "CoGetCallerTID", "ole32");

//
// ADVAPI32 function definitions
//
pub const OpenProcessToken = def(?PFN_OpenProcessToken, "OpenProcessToken", "advapi32");
pub const GetTokenInformation = def(?PFN_GetTokenInformation, "GetTokenInformation", "advapi32");

//
// WS2_32 function definitions
//
pub const WSAStartup = def(?PFN_WSAStartup, "WSAStartup", "ws2_32");
pub const WSACleanup = def(?PFN_WSACleanup, "WSACleanup", "ws2_32");
pub const WSAGetLastError = def(?PFN_WSAGetLastError, "WSAGetLastError", "ws2_32");
pub const WSASocketW = def(?PFN_WSASocketW, "WSASocketW", "ws2_32");
pub const WSAPoll = def(?PFN_WSAPoll, "WSAPoll", "ws2_32");
pub const WSASendTo = def(?PFN_WSASendTo, "WSASendTo", "ws2_32");
pub const WSARecvFrom = def(?PFN_WSARecvFrom, "WSARecvFrom", "ws2_32");
pub const closesocket = def(?PFN_closesocket, "closesocket", "ws2_32");
pub const getaddrinfo = def(?PFN_getaddrinfo, "getaddrinfo", "ws2_32");
pub const freeaddrinfo = def(?PFN_freeaddrinfo, "freeaddrinfo", "ws2_32");
pub const bind = def(?PFN_bind, "bind", "ws2_32");
pub const connect = def(?PFN_connect, "connect", "ws2_32");
pub const ioctlsocket = def(?PFN_ioctlsocket, "ioctlsocket", "ws2_32");
pub const getsockopt = def(?PFN_getsockopt, "getsockopt", "ws2_32");
pub const setsockopt = def(?PFN_setsockopt, "setsockopt", "ws2_32");

//
// Redirectors (for Cobalt Strike compat)
//
comptime {
    if (@import("builtin").mode != .Debug and @import("builtin").os.tag == .windows and bof) {
        @export(&RE_WriteFile, .{ .name = "WriteFile", .linkage = .strong });
        @export(&RE_ReadFile, .{ .name = "ReadFile", .linkage = .strong });
        @export(&RE_Sleep, .{ .name = "Sleep", .linkage = .strong });
        @export(&RE_VirtualAlloc, .{ .name = "VirtualAlloc", .linkage = .strong });
        @export(&RE_VirtualFree, .{ .name = "VirtualFree", .linkage = .strong });
        @export(&RE_ExitProcess, .{ .name = "ExitProcess", .linkage = .strong });
        @export(&RE_WSAStartup, .{ .name = "WSAStartup", .linkage = .strong });
        @export(&RE_WSACleanup, .{ .name = "WSACleanup", .linkage = .strong });
        @export(&RE_WSAGetLastError, .{ .name = "WSAGetLastError", .linkage = .strong });
        @export(&RE_WSASocketW, .{ .name = "WSASocketW", .linkage = .strong });
        @export(&RE_WSAPoll, .{ .name = "WSAPoll", .linkage = .strong });
        @export(&RE_WSASendTo, .{ .name = "WSASendTo", .linkage = .strong });
        @export(&RE_WSARecvFrom, .{ .name = "WSARecvFrom", .linkage = .strong });
        @export(&RE_closesocket, .{ .name = "closesocket", .linkage = .strong });
        @export(&RE_getaddrinfo, .{ .name = "getaddrinfo", .linkage = .strong });
        @export(&RE_freeaddrinfo, .{ .name = "freeaddrinfo", .linkage = .strong });
        @export(&RE_bind, .{ .name = "bind", .linkage = .strong });
        @export(&RE_connect, .{ .name = "connect", .linkage = .strong });
        @export(&RE_ioctlsocket, .{ .name = "ioctlsocket", .linkage = .strong });
        @export(&RE_getsockopt, .{ .name = "getsockopt", .linkage = .strong });
        @export(&RE_setsockopt, .{ .name = "setsockopt", .linkage = .strong });
        @export(&RE_NtClose, .{ .name = "NtClose", .linkage = .strong });
        @export(&RE_NtCreateFile, .{ .name = "NtCreateFile", .linkage = .strong });
        @export(&RE_RtlSetCurrentDirectory_U, .{ .name = "RtlSetCurrentDirectory_U", .linkage = .strong });
        @export(&RE_RtlGetSystemTimePrecise, .{ .name = "RtlGetSystemTimePrecise", .linkage = .strong });
        @export(&RE_RtlGetFullPathName_U, .{ .name = "RtlGetFullPathName_U", .linkage = .strong });
        @export(&RE_NtQueryDirectoryFile, .{ .name = "NtQueryDirectoryFile", .linkage = .strong });
        @export(&RE_NtQueryObject, .{ .name = "NtQueryObject", .linkage = .strong });
        @export(&RE_NtLockFile, .{ .name = "NtLockFile", .linkage = .strong });
        @export(&RE_NtDeviceIoControlFile, .{ .name = "NtDeviceIoControlFile", .linkage = .strong });
        @export(&RE_NtFsControlFile, .{ .name = "NtFsControlFile", .linkage = .strong });
        @export(&RE_GetCurrentDirectoryW, .{ .name = "GetCurrentDirectoryW", .linkage = .strong });
    }
}

// This section can be removed from BOF:
// llvm-strip.exe --remove-section=section_name --no-strip-all <BOF>
// TODO: Automate this?
const re_section = ".text";

fn RE_WriteFile(
    hFile: HANDLE,
    lpBuffer: LPCVOID,
    nNumberOfBytesToWrite: DWORD,
    lpNumberOfBytesWritten: ?*DWORD,
    lpOverlapped: ?*OVERLAPPED,
) linksection(re_section) callconv(.winapi) BOOL {
    return WriteFile.?(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}
fn RE_ReadFile(
    hFile: HANDLE,
    lpBuffer: LPVOID,
    nNumberOfBytesToRead: DWORD,
    lpNumberOfBytesRead: ?*DWORD,
    lpOverlapped: ?*OVERLAPPED,
) linksection(re_section) callconv(.winapi) BOOL {
    return ReadFile.?(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}
fn RE_Sleep(dwMilliseconds: DWORD) linksection(re_section) callconv(.winapi) void {
    Sleep.?(dwMilliseconds);
}
fn RE_VirtualAlloc(
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    flAllocationType: DWORD,
    flProtect: DWORD,
) linksection(re_section) callconv(.winapi) ?LPVOID {
    return VirtualAlloc.?(lpAddress, dwSize, flAllocationType, flProtect);
}
fn RE_VirtualFree(
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    dwFreeType: DWORD,
) linksection(re_section) callconv(.winapi) BOOL {
    return VirtualFree.?(lpAddress, dwSize, dwFreeType);
}
fn RE_ExitProcess(uExitCode: UINT) linksection(re_section) callconv(.winapi) void {
    ExitProcess.?(uExitCode);
}
fn RE_WSAStartup(
    wVersionRequired: WORD,
    lpWSAData: *WSADATA,
) linksection(re_section) callconv(.winapi) i32 {
    return WSAStartup.?(wVersionRequired, lpWSAData);
}
fn RE_WSACleanup() linksection(re_section) callconv(.winapi) i32 {
    return WSACleanup.?();
}
fn RE_WSAGetLastError() linksection(re_section) callconv(.winapi) i32 {
    return WSAGetLastError.?();
}
fn RE_WSASocketW(
    af: i32,
    @"type": i32,
    protocol: i32,
    lpProtocolInfo: ?*WSAPROTOCOL_INFOW,
    g: u32,
    dwFlags: u32,
) linksection(re_section) callconv(.winapi) SOCKET {
    return WSASocketW.?(af, @"type", protocol, lpProtocolInfo, g, dwFlags);
}
fn RE_WSAPoll(
    fdArray: [*]WSAPOLLFD,
    fds: u32,
    timeout: i32,
) linksection(re_section) callconv(.winapi) i32 {
    return WSAPoll.?(fdArray, fds, timeout);
}
fn RE_WSASendTo(
    s: SOCKET,
    lpBuffers: [*]WSABUF,
    dwBufferCount: u32,
    lpNumberOfBytesSent: ?*u32,
    dwFlags: u32,
    lpTo: ?*const sockaddr,
    iToLen: i32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRounte: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) linksection(re_section) callconv(.winapi) i32 {
    return WSASendTo.?(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRounte);
}
fn RE_WSARecvFrom(
    s: SOCKET,
    lpBuffers: [*]WSABUF,
    dwBufferCount: u32,
    lpNumberOfBytesRecvd: ?*u32,
    lpFlags: *u32,
    lpFrom: ?*sockaddr,
    lpFromLen: ?*i32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRoutine: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) linksection(re_section) callconv(.winapi) i32 {
    return WSARecvFrom.?(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromLen, lpOverlapped, lpCompletionRoutine);
}
fn RE_closesocket(s: SOCKET) linksection(re_section) callconv(.winapi) i32 {
    return closesocket.?(s);
}
fn RE_getaddrinfo(
    pNodeName: ?[*:0]const u8,
    pServiceName: ?[*:0]const u8,
    pHints: ?*const addrinfoa,
    ppResult: *?*addrinfoa,
) linksection(re_section) callconv(.winapi) i32 {
    return getaddrinfo.?(pNodeName, pServiceName, pHints, ppResult);
}
fn RE_freeaddrinfo(pAddrInfo: ?*addrinfoa) linksection(re_section) callconv(.winapi) void {
    freeaddrinfo.?(pAddrInfo);
}
fn RE_bind(
    s: SOCKET,
    name: *const sockaddr,
    namelen: i32,
) linksection(re_section) callconv(.winapi) i32 {
    return bind.?(s, name, namelen);
}
fn RE_connect(
    s: SOCKET,
    name: *const sockaddr,
    namelen: i32,
) linksection(re_section) callconv(.winapi) i32 {
    return connect.?(s, name, namelen);
}
fn RE_ioctlsocket(
    s: SOCKET,
    cmd: i32,
    argp: *u32,
) linksection(re_section) callconv(.winapi) i32 {
    return ioctlsocket.?(s, cmd, argp);
}
fn RE_getsockopt(
    s: SOCKET,
    level: i32,
    optname: i32,
    optval: [*]u8,
    optlen: *i32,
) linksection(re_section) callconv(.winapi) i32 {
    return getsockopt.?(s, level, optname, optval, optlen);
}
fn RE_setsockopt(
    s: SOCKET,
    level: i32,
    optname: i32,
    optval: ?[*]const u8,
    optlen: i32,
) linksection(re_section) callconv(.winapi) i32 {
    return setsockopt.?(s, level, optname, optval, optlen);
}
fn RE_NtClose(hHandle: HANDLE) linksection(re_section) callconv(.winapi) NTSTATUS {
    return NtClose.?(hHandle);
}
fn RE_NtCreateFile(
    FileHandle: *HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: *OBJECT_ATTRIBUTES,
    IoStatusBlock: *IO_STATUS_BLOCK,
    AllocationSize: ?*LARGE_INTEGER,
    FileAttributes: ULONG,
    ShareAccess: ULONG,
    CreateDisposition: ULONG,
    CreateOptions: ULONG,
    EaBuffer: ?*anyopaque,
    EaLength: ULONG,
) linksection(re_section) callconv(.winapi) NTSTATUS {
    return NtCreateFile.?(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}
fn RE_RtlSetCurrentDirectory_U(PathName: *UNICODE_STRING) linksection(re_section) callconv(.winapi) NTSTATUS {
    return RtlSetCurrentDirectory_U.?(PathName);
}
fn RE_RtlGetSystemTimePrecise() linksection(re_section) callconv(.winapi) LARGE_INTEGER {
    return RtlGetSystemTimePrecise.?();
}
fn RE_RtlGetFullPathName_U(
    FileName: [*:0]const u16,
    BufferByteLength: ULONG,
    Buffer: [*]u16,
    ShortName: ?*[*:0]const u16,
) linksection(re_section) callconv(.winapi) ULONG {
    return RtlGetFullPathName_U.?(FileName, BufferByteLength, Buffer, ShortName);
}
fn RE_NtQueryDirectoryFile(
    FileHandle: HANDLE,
    Event: ?HANDLE,
    ApcRoutine: ?IO_APC_ROUTINE,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *IO_STATUS_BLOCK,
    FileInformation: *anyopaque,
    Length: ULONG,
    FileInformationClass: FILE_INFORMATION_CLASS,
    ReturnSingleEntry: BOOLEAN,
    FileName: ?*UNICODE_STRING,
    RestartScan: BOOLEAN,
) linksection(re_section) callconv(.winapi) NTSTATUS {
    return NtQueryDirectoryFile.?(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
}
fn RE_NtQueryObject(
    Handle: HANDLE,
    ObjectInformationClass: OBJECT_INFORMATION_CLASS,
    ObjectInformation: PVOID,
    ObjectInformationLength: ULONG,
    ReturnLength: ?*ULONG,
) linksection(re_section) callconv(.winapi) NTSTATUS {
    return NtQueryObject.?(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
}
fn RE_NtLockFile(
    FileHandle: HANDLE,
    Event: ?HANDLE,
    ApcRoutine: ?*IO_APC_ROUTINE,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *IO_STATUS_BLOCK,
    ByteOffset: *const LARGE_INTEGER,
    Length: *const LARGE_INTEGER,
    Key: ?*ULONG,
    FailImmediately: BOOLEAN,
    ExclusiveLock: BOOLEAN,
) linksection(re_section) callconv(.winapi) NTSTATUS {
    return NtLockFile.?(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, ByteOffset, Length, Key, FailImmediately, ExclusiveLock);
}
fn RE_NtDeviceIoControlFile(
    FileHandle: HANDLE,
    Event: ?HANDLE,
    ApcRoutine: ?IO_APC_ROUTINE,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *IO_STATUS_BLOCK,
    IoControlCode: ULONG,
    InputBuffer: ?*const anyopaque,
    InputBufferLength: ULONG,
    OutputBuffer: ?PVOID,
    OutputBufferLength: ULONG,
) linksection(re_section) callconv(.winapi) NTSTATUS {
    return NtDeviceIoControlFile.?(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}
fn RE_NtFsControlFile(
    FileHandle: HANDLE,
    Event: ?HANDLE,
    ApcRoutine: ?IO_APC_ROUTINE,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *IO_STATUS_BLOCK,
    FsControlCode: ULONG,
    InputBuffer: ?*const anyopaque,
    InputBufferLength: ULONG,
    OutputBuffer: ?PVOID,
    OutputBufferLength: ULONG,
) linksection(re_section) callconv(.winapi) NTSTATUS {
    return NtFsControlFile.?(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FsControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}
fn RE_GetCurrentDirectoryW(
    nBufferLength: DWORD,
    lpBuffer: ?[*]WCHAR,
) linksection(re_section) callconv(.winapi) DWORD {
    return GetCurrentDirectoryW.?(nBufferLength, lpBuffer);
}
