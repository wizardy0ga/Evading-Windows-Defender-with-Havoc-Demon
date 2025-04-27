/*
	Generated with hashycalls script version 1.2.0. Template version is 1.0.0
	Generated with the command line: .\HashyCalls.py --apicalls NtFlushInstructionCache
*/
# pragma once
# include <windows.h>

# define HASH_SEED_             7678
# define KERNEL32_              0xE9D4CA70
# define NTDLL_                 0x9A43FD96
# define KERNELBASE_            0x270FA3E2
# define WINDIR                 0xB5C6476F
# define SYSTEM32               0xC532BBAC
# define LoadLibraryA_Hash      0x39819FEA
# define FindFirstFileA_Hash    0x7D1E456C
# define FindNextFileA_Hash     0xBDC485FB

#define NtFlushInstructionCache_Hash 0x20F23734

typedef BOOL(WINAPI* fpNtFlushInstructionCache)(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T RegionSize);

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

typedef struct _CURDIR_
{
    UNICODE_STRING_ DosPath;
    HANDLE Handle;
} CURDIR_, * PCURDIR_;

typedef struct _RTL_USER_PROCESS_PARAMETERS_
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
    CURDIR_ CurrentDirectory;
    UNICODE_STRING_ DllPath;
    UNICODE_STRING_ ImagePathName;
    UNICODE_STRING_ CommandLine;
    PVOID Environment;
} RTL_USER_PROCESS_PARAMETERS_, * PRTL_USER_PROCESS_PARAMETERS_;

typedef struct _PROC_ENV_BLOCK
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LOADER_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS_ ProcessParameters;
} PROC_ENV_BLOCK, * PPROC_ENV_BLOCK;

typedef HMODULE(WINAPI* fpLoadLibraryA)(LPCSTR lpLibFileName);
typedef HANDLE(WINAPI* fpFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(WINAPI* fpFindNextFileA)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);

#define LOCATE_KERNEL32_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(KERNEL32_), ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

#define LOCATE_KERNELBASE_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(KERNELBASE_), ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

#define LOCATE_NTDLL_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(NTDLL_), ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

/* Temporarily disabled pending future update to base template */
// #define LOCATE_FUNCTION(ApiCallName, ModuleHash) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(ModuleHash), ApiCallName##_Hash); \
// if (!ApiCallName##_) { return FALSE; }\


DWORD HashString(IN PCHAR String) {
    ULONG Hash = HASH_SEED_;
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
    int     Index   = 0;
    char    Letter  = 0;
    for (Index = 0; Index < StringLengthA(String); Index++) {
        Letter = (char)String[Index];
        String[Index] = (Letter >= 'A' && Letter <= 'Z') ? Letter + 0x20 : Letter;
    }
}

HMODULE GetModuleHandleByHash(IN DWORD Hash) {

    CHAR ModuleNameLowerCase[MAX_PATH];
    CHAR Letter = 0;
    UINT Index  = 0;
    PLOADER_DATA_TABLE_ENTRY pModule = 0;
    PPROC_ENV_BLOCK pPeb = (PPROC_ENV_BLOCK)__readgsqword(0x60);
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

    ULONG_PTR         Base  = (ULONG_PTR)hModule;
    PIMAGE_DOS_HEADER pDos  = (PIMAGE_DOS_HEADER)Base;
    PIMAGE_NT_HEADERS pNt   = (PIMAGE_NT_HEADERS)(Base + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    PIMAGE_EXPORT_DIRECTORY     pExportDir  = (PIMAGE_EXPORT_DIRECTORY)(Base + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD                      pAddresses  = (PDWORD)(Base + pExportDir->AddressOfFunctions),
                                pNames      = (PDWORD)(Base + pExportDir->AddressOfNames);
    PWORD                       pOrdinals   = (PWORD)(Base + pExportDir->AddressOfNameOrdinals);
    PIMAGE_SECTION_HEADER       pSection = IMAGE_FIRST_SECTION(pNt),
                                pText = 0;

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
