const std = @import("std");
const windows = std.os.windows;

pub const ATTACH_PARENT_PROCESS = 0xffff_ffff;

pub const Win32Error = windows.Win32Error;
pub const ULONG = windows.ULONG;
pub const WCHAR = windows.WCHAR;
pub const LPCSTR = windows.LPCSTR;
pub const WINAPI = windows.WINAPI;
pub const HMODULE = windows.HMODULE;
pub const FARPROC = windows.FARPROC;
pub const HANDLE = windows.HANDLE;
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
pub const PROCESS_VM_OPERATION = 0x0008;
pub const PROCESS_CREATE_THREAD = 0x0002;
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

// kernel32
pub const VirtualAlloc = windows.kernel32.VirtualAlloc;
pub const VirtualFree = windows.kernel32.VirtualFree;
pub const GetLastError = windows.kernel32.GetLastError;
pub const Sleep = windows.kernel32.Sleep;
pub const ExitProcess = windows.kernel32.ExitProcess;
pub const GetCurrentProcess = windows.kernel32.GetCurrentProcess;
pub const WaitForSingleObject = windows.kernel32.WaitForSingleObject;
pub const ReadFile = windows.kernel32.ReadFile;
pub const WriteFile = windows.kernel32.WriteFile;
pub const CloseHandle = windows.kernel32.CloseHandle;
pub const GetCurrentProcessId = windows.kernel32.GetCurrentProcessId;
pub const GetCurrentThreadId = windows.kernel32.GetCurrentThreadId;
pub const GetCurrentThread = windows.kernel32.GetCurrentThread;
pub const FreeLibrary = windows.kernel32.FreeLibrary;
pub const CreateThread = windows.kernel32.CreateThread;

pub extern "kernel32" fn FreeConsole() callconv(WINAPI) BOOL;

pub extern "kernel32" fn AttachConsole(
    dwProcessId: DWORD,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn IsWow64Process(
    hProcess: HANDLE,
    Wow64Process: *BOOL,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn GetExitCodeProcess(
    hProcess: HANDLE,
    lpExitCode: *DWORD,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn GetModuleHandleA(
    lpModuleName: ?LPCSTR,
) callconv(WINAPI) ?HMODULE;

pub extern "kernel32" fn LoadLibraryA(
    lpLibFileName: LPCSTR,
) callconv(WINAPI) ?HMODULE;

pub extern "kernel32" fn GetProcAddress(
    hModule: HMODULE,
    lpProcName: LPCSTR,
) callconv(WINAPI) ?FARPROC;

pub extern "kernel32" fn CreatePipe(
    hReadPipe: *HANDLE,
    hWritePipe: *HANDLE,
    lpPipeAttributes: ?*const SECURITY_ATTRIBUTES,
    nSize: DWORD,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn ResumeThread(
    hThread: HANDLE,
) callconv(WINAPI) DWORD;

// ntdll
pub const RtlGetVersion = windows.ntdll.RtlGetVersion;
pub const NtQueryInformationProcess = windows.ntdll.NtQueryInformationProcess;

pub fn NtCurrentProcess() HANDLE {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
}
pub fn NtCurrentThread() HANDLE {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, -2))));
}
pub fn NtCurrentSession() HANDLE {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, -3))));
}

pub extern "ntdll" fn RtlCloneUserProcess(
    ProcessFlags: ULONG,
    ProcessSecurityDescriptor: ?PSECURITY_DESCRIPTOR,
    ThreadSecurityDescriptor: ?PSECURITY_DESCRIPTOR,
    DebugPort: ?HANDLE,
    ProcessInformation: *RTL_USER_PROCESS_INFORMATION,
) callconv(WINAPI) NTSTATUS;

pub extern "ntdll" fn NtResumeThread(
    ThreadHandle: HANDLE,
    PreviousSuspendCount: ?*ULONG,
) callconv(WINAPI) NTSTATUS;

pub extern "ntdll" fn NtSuspendThread(
    ThreadHandle: HANDLE,
    PreviousSuspendCount: ?*ULONG,
) callconv(WINAPI) NTSTATUS;

pub extern "ntdll" fn NtTerminateThread(
    ThreadHandle: ?HANDLE,
    ExitStatus: NTSTATUS,
) callconv(WINAPI) NTSTATUS;

pub extern "ntdll" fn NtTerminateProcess(
    ProcessHandle: ?HANDLE,
    ExitStatus: NTSTATUS,
) callconv(WINAPI) NTSTATUS;

pub extern "ntdll" fn NtOpenProcess(
    ProcessHandle: *HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: *OBJECT_ATTRIBUTES,
    ClientId: ?*CLIENT_ID,
) callconv(WINAPI) NTSTATUS;

pub extern "ntdll" fn NtResumeProcess(
    ProcessHandle: HANDLE,
) callconv(WINAPI) NTSTATUS;

pub extern "ntdll" fn NtSuspendProcess(
    ProcessHandle: HANDLE,
) callconv(WINAPI) NTSTATUS;

pub extern "ntdll" fn NtCreateJobObject(
    JobHandle: *HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: ?*OBJECT_ATTRIBUTES,
) callconv(WINAPI) NTSTATUS;

pub extern "ntdll" fn NtAssignProcessToJobObject(
    JobHandle: HANDLE,
    ProcessHandle: HANDLE,
) callconv(WINAPI) NTSTATUS;

pub extern "ntdll" fn NtTerminateJobObject(
    JobHandle: HANDLE,
    ExitStatus: NTSTATUS,
) callconv(WINAPI) NTSTATUS;

pub extern "ntdll" fn NtIsProcessInJob(
    ProcessHandle: HANDLE,
    JobHandle: ?HANDLE,
) callconv(WINAPI) NTSTATUS;

pub extern "ntdll" fn NtSetInformationJobObject(
    JobHandle: HANDLE,
    JobObjectInformationClass: JOBOBJECTINFOCLASS,
    JobObjectInformation: PVOID,
    JobObjectInformationLength: ULONG,
) callconv(WINAPI) NTSTATUS;

pub extern "ntdll" fn NtClose(
    Handle: HANDLE,
) callconv(WINAPI) NTSTATUS;

pub extern "ntdll" fn RtlWow64EnableFsRedirection(
    Wow64FsEnableRedirection: BOOLEAN,
) callconv(WINAPI) NTSTATUS;

pub extern "ntdll" fn NtAllocateVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: *PVOID,
    ZeroBits: ULONG_PTR,
    RegionSize: *SIZE_T,
    AllocationType: ULONG,
    Protect: ULONG,
) callconv(WINAPI) NTSTATUS;

pub const NtWriteVirtualMemory = windows.ntdll.NtWriteVirtualMemory;
pub const NtProtectVirtualMemory = windows.ntdll.NtProtectVirtualMemory;

pub extern "ntdll" fn NtCreateThreadEx(
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
) callconv(WINAPI) NTSTATUS;

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

pub extern "ntdll" fn NtCreateUserProcess(
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
) callconv(WINAPI) NTSTATUS;

// advapi32
pub extern "advapi32" fn OpenProcessToken(
    ProcessHandle: HANDLE,
    DesiredAccess: DWORD,
    TokenHandle: *HANDLE,
) callconv(WINAPI) BOOL;

pub extern "advapi32" fn GetTokenInformation(
    TokenHandle: HANDLE,
    TokenInformationClass: TOKEN_INFORMATION_CLASS,
    TokenInformation: ?*anyopaque,
    TokenInformationLength: DWORD,
    ReturnLength: *DWORD,
) callconv(WINAPI) BOOL;

// user32
pub const MessageBoxA = windows.user32.MessageBoxA;

// ole32
pub extern "ole32" fn CoInitializeEx(pvReserved: ?LPVOID, dwCoInit: DWORD) callconv(WINAPI) HRESULT;
pub extern "ole32" fn CoUninitialize() callconv(WINAPI) void;
pub extern "ole32" fn CoTaskMemAlloc(size: SIZE_T) callconv(WINAPI) ?LPVOID;
pub extern "ole32" fn CoTaskMemFree(pv: LPVOID) callconv(WINAPI) void;
pub extern "ole32" fn CoGetCurrentProcess() callconv(WINAPI) DWORD;
pub extern "ole32" fn CoGetCallerTID(lpdwTID: *DWORD) callconv(WINAPI) HRESULT;

// ws2_32
pub const WSAStartup = windows.ws2_32.WSAStartup;
pub const WSACleanup = windows.ws2_32.WSACleanup;
pub const WSASocketW = windows.ws2_32.WSASocketW;
pub const WSAGetLastError = windows.ws2_32.WSAGetLastError;
pub const closesocket = windows.ws2_32.closesocket;
