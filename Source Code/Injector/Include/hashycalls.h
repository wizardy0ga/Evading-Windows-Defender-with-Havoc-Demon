/*
    Generated with hashycalls script version 1.2.0. Template version is 1.0.0
    Generated with the command line: .\HashyCalls.py --file .\a.txt -ga
    Imported API Calls:
         - InternetOpenA
         - InternetOpenUrlA
         - InternetReadFile
         - LocalAlloc
         - LocalReAlloc
         - CreateToolhelp32Snapshot
         - Process32NextW
         - Process32FirstW
*/
# pragma once
# include <windows.h>

# define HASH_SEED                      6850
# define KERNEL32                       0x6196FB34
# define NTDLL                          0x5A7B9D2
# define KERNELBASE                     0xE13DB2A6
# define WINDIR                         0x2EADE33
# define SYSTEM32                       0xFDF03070
# define LoadLibraryA_Hash              0xB143D0AE
# define FindFirstFileA_Hash            0x374C5430
# define FindNextFileA_Hash             0x67528637

# define InternetOpenA_Hash             0x53043474
# define InternetOpenUrlA_Hash          0x8290B3BF
# define InternetReadFile_Hash          0x79AB87D5
# define LocalAlloc_Hash                0x18ECDB2C
# define LocalReAlloc_Hash              0xFE1272D9
# define CreateToolhelp32Snapshot_Hash  0xB019A09A
# define Process32NextW_Hash            0xC40E2B8
# define Process32FirstW_Hash           0x2D7450D3


# define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                         \
    (p)->Attributes = a;                            \
    (p)->ObjectName = n;                            \
    (p)->SecurityDescriptor = s;                    \
    (p)->SecurityQualityOfService = NULL;           \
}

typedef LPVOID      HINTERNET;
typedef HINTERNET*  LPHINTERNET;

typedef struct tagPROCESSENTRY32W
{
    DWORD   dwSize;
    DWORD   cntUsage;
    DWORD   th32ProcessID;          // this process
    ULONG_PTR th32DefaultHeapID;
    DWORD   th32ModuleID;           // associated exe
    DWORD   cntThreads;
    DWORD   th32ParentProcessID;    // this process's parent process
    LONG    pcPriClassBase;         // Base priority of process's threads
    DWORD   dwFlags;
    WCHAR   szExeFile[MAX_PATH];    // Path
} PROCESSENTRY32, * PPROCESSENTRY32;

typedef HINTERNET(WINAPI* fpInternetOpenA)          (LPCTSTR lpszAgent, DWORD dwAccessType, LPCTSTR lpszProxyName, LPCTSTR lpszProxyBypass, DWORD dwFlags);
typedef HINTERNET(WINAPI* fpInternetOpenUrlA)       (HINTERNET hInternet, LPCTSTR lpszUrl, LPCTSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext);
typedef BOOL(WINAPI* fpInternetReadFile)            (HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
typedef HLOCAL(WINAPI* fpLocalAlloc)                (UINT uFlags, SIZE_T uBytes);
typedef HLOCAL(WINAPI* fpLocalReAlloc)              (HLOCAL hMem, SIZE_T uBytes, UINT uFlags);
typedef HANDLE(WINAPI* fpCreateToolhelp32Snapshot)  (DWORD dwFlags, DWORD th32ProcessIDCopyright);
typedef BOOL(WINAPI* fpProcess32NextW)              (HANDLE hSnapshot, LPVOID lppe);
typedef BOOL(WINAPI* fpProcess32FirstW)             (HANDLE hSnapshot, LPVOID lppe);

typedef struct _UNICODE_STRING_
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING_, * PUNICODE_STRING_;

typedef struct _LOADER_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING_ FullDllName;
    UNICODE_STRING_ BaseDllName;
} LOADER_DATA_TABLE_ENTRY, * PLOADER_DATA_TABLE_ENTRY;

typedef struct _PEB_LOADER_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LOADER_DATA, * PPEB_LOADER_DATA;

typedef struct _CURDIR
{
    UNICODE_STRING_ DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING_ DllPath;
    UNICODE_STRING_ ImagePathName;
    UNICODE_STRING_ CommandLine;
    PVOID Environment;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PROC_ENV_BLOCK
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LOADER_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
} PROC_ENV_BLOCK, * PPROC_ENV_BLOCK;

typedef HMODULE(WINAPI* fpLoadLibraryA)(LPCSTR lpLibFileName);
typedef HANDLE(WINAPI* fpFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(WINAPI* fpFindNextFileA)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);

#define LOCATE_KERNEL32_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(KERNEL32), ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

#define LOCATE_KERNELBASE_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(KERNELBASE), ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

#define LOCATE_NTDLL_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(NTDLL), ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\



DWORD HashString(IN PCHAR String) {
    ULONG Hash = HASH_SEED;
    INT c;

    while (c = *String++)
        Hash = c + (Hash << 6) + (Hash << 16) - Hash;

    return Hash;
}

SIZE_T StringLengthA(_In_ LPCSTR String)
{
    LPCSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

VOID WCharToChar(OUT PCHAR Dest, IN PWCHAR Source) {
    while (TRUE) {
        if (!(*Dest++ = (CHAR)*Source++)) {
            break;
        }
    }
}

SIZE_T StringLengthW(_In_ LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

PCHAR StringCopyA(_Inout_ PCHAR String1, _In_ LPCSTR String2)
{
    PCHAR p = String1;

    while ((*p++ = *String2++) != 0);

    return String1;
}

PCHAR StringConcatA(_Inout_ PCHAR String, _In_ LPCSTR String2)
{
    StringCopyA(&String[StringLengthA(String)], String2);

    return String;
}

VOID ToLower(IN PCHAR String) {
    int Index = 0;
    char Letter = 0;
    for (Index = 0; Index < StringLengthA(String); Index++) {
        Letter = (char)String[Index];
        String[Index] = (Letter >= 'A' && Letter <= 'Z') ? Letter + 0x20 : Letter;
    }
}

HMODULE GetModuleHandleByHash(IN DWORD Hash) {

    CHAR                        ModuleNameLowerCase[MAX_PATH];
    CHAR                        Letter      = 0;
    UINT                        Index       = 0;
    PLOADER_DATA_TABLE_ENTRY    pModule     = 0;
    PPROC_ENV_BLOCK             pPeb        = (PPROC_ENV_BLOCK)__readgsqword(0x60);
    if (!pPeb) {
        return NULL;
    }

    for (pModule = (PLOADER_DATA_TABLE_ENTRY)pPeb->Ldr->InLoadOrderModuleList.Flink; pModule->DllBase != NULL; pModule = (PLOADER_DATA_TABLE_ENTRY)pModule->InLoadOrderLinks.Flink) {
        if (pModule->BaseDllName.Length && pModule->BaseDllName.Length < MAX_PATH) {
            for (Index = 0; Index < pModule->BaseDllName.Length; Index++) {
                Letter = (CHAR)(pModule->BaseDllName.Buffer[Index]);
                ModuleNameLowerCase[Index] = (Letter >= 'A' && Letter <= 'Z' && Letter != 0x00) ? Letter + 0x20 : Letter;
            }
            ModuleNameLowerCase[Index++] = '\0';
            if (HashString(ModuleNameLowerCase) == Hash) {
                return (HMODULE)(pModule->DllBase);
            }
        }
    }
    return NULL;
}

FARPROC GetProcAddressByHash(IN HMODULE hModule, IN DWORD Hash) {

    ULONG_PTR           Base    = (ULONG_PTR)hModule;
    PIMAGE_DOS_HEADER   pDos    = (PIMAGE_DOS_HEADER)Base;
    PIMAGE_NT_HEADERS   pNt     = (PIMAGE_NT_HEADERS)(Base + pDos->e_lfanew);
    
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    PIMAGE_EXPORT_DIRECTORY     pExportDir  = (PIMAGE_EXPORT_DIRECTORY)(Base + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD                      pAddresses  = (PDWORD)(Base + pExportDir->AddressOfFunctions),
                                pNames      = (PDWORD)(Base + pExportDir->AddressOfNames);
    PWORD                       pOrdinals   = (PWORD)(Base + pExportDir->AddressOfNameOrdinals);
    PIMAGE_SECTION_HEADER       pSection    = IMAGE_FIRST_SECTION(pNt),
                                pText       = 0;

    for (unsigned int i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSection++) {
        if (pSection->Characteristics & IMAGE_SCN_MEM_READ && pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            pText = pSection;
            break;
        }
    }

    for (unsigned int i = 0; i < pExportDir->NumberOfFunctions; i++) {
        if (HashString((PCHAR)(Base + pNames[i])) == Hash) {
            ULONG_PTR FunctionAddress = Base + pAddresses[pOrdinals[i]];

            if (FunctionAddress >= (Base + pText->SizeOfRawData)) {

                CHAR ModuleName[MAX_PATH] = { 0 };
                ULONG_PTR Offset = 0;
                CHAR C = 0;
                int j = 0;

                while (C = *(PCHAR)(FunctionAddress + j)) {
                    if (C == '.') {
                        Offset = j + 1;
                        break;
                    }
                    else {
                        ModuleName[j] = C;
                    }
                    j++;
                }

                LOCATE_KERNEL32_FUNCTION(LoadLibraryA);

                HMODULE hModule = LoadLibraryA_(ModuleName);
                if (!hModule) {
                    return NULL;
                }

                FunctionAddress = (ULONG_PTR)GetProcAddressByHash(hModule, HashString((PCHAR)(FunctionAddress + Offset)));
            }
            return (FARPROC)FunctionAddress;
        }
    }

    return 0;
}

#define GET_FUNCTION_CALL(FunctionName) fp##FunctionName FunctionName##_ = (fp##FunctionName)(&HashedAPI)->##FunctionName.Address

typedef struct _API_CALL {
    DWORD Hash;
    PVOID Address;
    DWORD ModuleHash;
    HMODULE hModule;
} API_CALL, * PAPI_CALL;

typedef struct _API_CALL_LIST {
    API_CALL InternetOpenA;
    API_CALL InternetOpenUrlA;
    API_CALL InternetReadFile;
    API_CALL LocalAlloc;
    API_CALL LocalReAlloc;
    API_CALL CreateToolhelp32Snapshot;
    API_CALL Process32NextW;
    API_CALL Process32FirstW;
    BOOL Initialized;
} API_CALL_LIST, * PAPI_CALL_LIST;


API_CALL_LIST HashedAPI = {
    .InternetOpenA.Hash = 0x7CD4A70A,
    .InternetOpenA.ModuleHash = 0x60C0C85A,
    .InternetOpenUrlA.Hash = 0xB411A9,
    .InternetOpenUrlA.ModuleHash = 0x60C0C85A,
    .InternetReadFile.Hash = 0xF7CEE5BF,
    .InternetReadFile.ModuleHash = 0x60C0C85A,
    .LocalAlloc.Hash = 0xDC9C3816,
    .LocalAlloc.ModuleHash = 0xFE92831E,
    .LocalReAlloc.Hash = 0x9B0DFAC3,
    .LocalReAlloc.ModuleHash = 0xFE92831E,
    .CreateToolhelp32Snapshot.Hash = 0x77CAAA84,
    .CreateToolhelp32Snapshot.ModuleHash = 0xFE92831E,
    .Process32NextW.Hash = 0xC92315A2,
    .Process32NextW.ModuleHash = 0xFE92831E,
    .Process32FirstW.Hash = 0xDC08D869,
    .Process32FirstW.ModuleHash = 0xFE92831E,
};

SIZE_T GetEnvVarByHash(IN DWORD Hash, OUT PCHAR OutBuffer) {
    PBYTE   pEnvironment = ((PPROC_ENV_BLOCK)__readgsqword(0x60))->ProcessParameters->Environment,
            pTmp;
    SIZE_T  StringSize;
    CHAR    VarNameBufferW[MAX_PATH];
    CHAR    VarNameBufferA[MAX_PATH];
    INT     Index = 0;

    while (TRUE) {
        if ((StringSize = StringLengthW((LPCWSTR)pEnvironment)) != 0) {
            pTmp = pEnvironment;
            Index = 0;

            while (*pTmp != '=') {
                VarNameBufferW[Index] = *pTmp++;
                Index++;
            }
            VarNameBufferW[Index] = '\0';
            WCharToChar(VarNameBufferA, (PWCHAR)VarNameBufferW);

            if (HashString(VarNameBufferA) == Hash) {
                WCharToChar(OutBuffer, (PWCHAR)(pEnvironment + Index + sizeof(WCHAR)));
                return StringLengthA(OutBuffer);
            }

        }
        else {
            break;
        }
        pEnvironment += (StringSize * sizeof(WCHAR)) + sizeof(WCHAR);
    }

    return FALSE;
}

HMODULE LoadDllFromSystem32ByHash(IN DWORD Hash) {

    WIN32_FIND_DATAA    FileData = { 0 };
    HANDLE              hFile;
    CHAR                DirSearchString[MAX_PATH];
    BOOL                System32Found = FALSE;

    LOCATE_KERNEL32_FUNCTION(LoadLibraryA);
    LOCATE_KERNEL32_FUNCTION(FindFirstFileA);
    LOCATE_KERNEL32_FUNCTION(FindNextFileA);

    SIZE_T VarSize = GetEnvVarByHash(WINDIR, DirSearchString);
    if (VarSize == 0 || VarSize > MAX_PATH)
        return NULL;
    StringConcatA(DirSearchString, "\\*");

    if ((hFile = FindFirstFileA_(DirSearchString, &FileData)) == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    do
    {
        if (HashString(FileData.cFileName) == SYSTEM32)
        {
            DirSearchString[StringLengthA(DirSearchString) - 1] = '\0';
            StringConcatA(DirSearchString, FileData.cFileName);
            StringConcatA(DirSearchString, "\\*");
            System32Found = TRUE;
        }
    } while (FindNextFileA_(hFile, &FileData) != 0 || System32Found != TRUE);

    if (!System32Found)
        return NULL;

    if ((hFile = FindFirstFileA_(DirSearchString, &FileData)) == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    do {
        ToLower(FileData.cFileName);
        if (HashString(FileData.cFileName) == Hash) {
            return LoadLibraryA_(FileData.cFileName);
        }
    } while (FindNextFileA_(hFile, &FileData) != 0);

    return NULL;
}

BOOL InitApiCalls() {
    PAPI_CALL pApiCall = (PAPI_CALL)&HashedAPI;
    if (!(&HashedAPI)->Initialized) {
        for (int i = 0; i < (sizeof(API_CALL_LIST) / sizeof(API_CALL)); i++) {
            if ((pApiCall->hModule = GetModuleHandleByHash(pApiCall->ModuleHash)) == NULL) {
                if ((pApiCall->hModule = LoadDllFromSystem32ByHash(pApiCall->ModuleHash)) == NULL) {
                    return FALSE;
                }
            }
            if ((pApiCall->Address = GetProcAddressByHash(pApiCall->hModule, pApiCall->Hash)) == NULL) {
                return FALSE;
            }
            (ULONG_PTR)pApiCall += sizeof(API_CALL);
        }
        (&HashedAPI)->Initialized = TRUE;
    }
    return TRUE;
}

