/*
	Generated with hashycalls script version 1.3.0. Template version is 1.1.0
	Generated with the command line: .\HashyCalls.py --file .\calls.txt -ga
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
#pragma once
#include <windows.h>

# define hc_DEBUG
# ifdef hc_DEBUG
# include <stdio.h>
# define hc_dbg(msg, ...) printf("[DEBUG]::Hashycalls.%s.L%d -> " msg "\n", __func__, __LINE__, ##__VA_ARGS__)
# endif

# ifndef hc_DEBUG
# define hc_dbg(msg, ...) do {} while (0)
# endif

# define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                         \
    (p)->Attributes = a;                            \
    (p)->ObjectName = n;                            \
    (p)->SecurityDescriptor = s;                    \
    (p)->SecurityQualityOfService = NULL;           \
}

typedef LPVOID      HINTERNET;
typedef HINTERNET* LPHINTERNET;

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

#define hc_HASH_SEED 2031
#define hc_KERNEL32 0x3B5D0161
#define hc_NTDLL 0xC17D31E5
#define hc_KERNELBASE 0x42897253
#define hc_WINDIR 0x78C337E0
#define hc_SYSTEM32 0x305C839D
#define hc_LoadLibraryA_Hash 0x8B09D6DB
#define hc_FindFirstFileA_Hash 0x989813DD
#define hc_FindNextFileA_Hash 0x53B0B4A

#define hc_InternetOpenA_Hash 0xF0ECB987
#define hc_InternetOpenUrlA_Hash 0x511D6CEC
#define hc_InternetReadFile_Hash 0x48384102
#define hc_LocalAlloc_Hash 0xCA8867D9
#define hc_LocalReAlloc_Hash 0xD7D87906
#define hc_CreateToolhelp32Snapshot_Hash 0x1C7ABFC7
#define hc_Process32NextW_Hash 0x6D8CA265
#define hc_Process32FirstW_Hash 0xDEC57C66


typedef HINTERNET(WINAPI* fpInternetOpenA)(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);
typedef HINTERNET(WINAPI* fpInternetOpenUrlA)(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext);
typedef BOOL(WINAPI* fpInternetReadFile)(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
typedef HLOCAL(WINAPI* fpLocalAlloc)(UINT uFlags, SIZE_T uBytes);
typedef HLOCAL(WINAPI* fpLocalReAlloc)(HLOCAL hMem, SIZE_T uBytes, UINT uFlags);
typedef HANDLE(WINAPI* fpCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);
typedef BOOL(WINAPI* fpProcess32NextW)(HANDLE hSnapshot, PPROCESSENTRY32 lppe);
typedef BOOL(WINAPI* fpProcess32FirstW)(HANDLE hSnapshot, PPROCESSENTRY32 lppe);

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

# define LOCATE_KERNEL32_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(hc_KERNEL32), hc_##ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

# define LOCATE_KERNELBASE_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(hc_KERNELBASE), hc_##ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

# define LOCATE_NTDLL_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(hc_NTDLL), hc_##ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

/* Temporarily disabled pending future update to base template */
// #define LOCATE_FUNCTION(ApiCallName, ModuleHash) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(ModuleHash), ApiCallName##_Hash); \
// if (!ApiCallName##_) { return FALSE; }\


DWORD HashString(IN PCHAR String) {
	ULONG Hash = hc_HASH_SEED;
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

	CHAR ModuleNameLowerCase[MAX_PATH];
	CHAR Letter = 0;
	UINT Index = 0;
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
				hc_dbg("Resolved 0x%0.8X to %s", Hash, ModuleNameLowerCase);
				return (HMODULE)(pModule->DllBase);
			}
		}
	}
	hc_dbg("Could not resolve 0x%0.8X to a DLL in the PEB", Hash);
	return NULL;
}

FARPROC GetProcAddressByHash(IN HMODULE hModule, IN DWORD Hash) {

	ULONG_PTR         Base = (ULONG_PTR)hModule;
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)Base;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(Base + pDos->e_lfanew);
	if (pNt->Signature != IMAGE_NT_SIGNATURE) {
		hc_dbg("NT Siganture mismatch. Got 0x%0.4X, Expected 0x%0.4X", pNt->Signature, IMAGE_NT_SIGNATURE);
		return 0;
	}

	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(Base + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD   pAddresses = (PDWORD)(Base + pExportDir->AddressOfFunctions),
		pNames = (PDWORD)(Base + pExportDir->AddressOfNames);
	PWORD    pOrdinals = (PWORD)(Base + pExportDir->AddressOfNameOrdinals);

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt),
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

			hc_dbg("Resolved 0x%0.8X to %s at 0x%p", Hash, (PCHAR)(Base + pNames[i]), (PVOID)FunctionAddress);
			return (FARPROC)FunctionAddress;
		}
	}

	hc_dbg("Could not resolve 0x%0.8X to any function address", Hash);
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
	.InternetOpenA.Hash = 0xF0ECB987,
	.InternetOpenA.ModuleHash = 0x1DA38957,
	.InternetOpenUrlA.Hash = 0x511D6CEC,
	.InternetOpenUrlA.ModuleHash = 0x1DA38957,
	.InternetReadFile.Hash = 0x48384102,
	.InternetReadFile.ModuleHash = 0x1DA38957,
	.LocalAlloc.Hash = 0xCA8867D9,
	.LocalAlloc.ModuleHash = 0x3B5D0161,
	.LocalReAlloc.Hash = 0xD7D87906,
	.LocalReAlloc.ModuleHash = 0x3B5D0161,
	.CreateToolhelp32Snapshot.Hash = 0x1C7ABFC7,
	.CreateToolhelp32Snapshot.ModuleHash = 0x3B5D0161,
	.Process32NextW.Hash = 0x6D8CA265,
	.Process32NextW.ModuleHash = 0x3B5D0161,
	.Process32FirstW.Hash = 0xDEC57C66,
	.Process32FirstW.ModuleHash = 0x3B5D0161,
};

SIZE_T GetEnvVarByHash(IN DWORD Hash, OUT PCHAR OutBuffer) {
	PBYTE pEnvironment = ((PPROC_ENV_BLOCK)__readgsqword(0x60))->ProcessParameters->Environment,
		pTmp;
	SIZE_T StringSize;
	CHAR VarNameBufferW[MAX_PATH];
	CHAR VarNameBufferA[MAX_PATH];
	INT Index = 0;

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
				hc_dbg("Resolved 0x%0.8X to (%s). Got value (%s).", Hash, VarNameBufferA, OutBuffer);
				return StringLengthA(OutBuffer);
			}

		}
		else {
			break;
		}
		pEnvironment += (StringSize * sizeof(WCHAR)) + sizeof(WCHAR);
	}
	hc_dbg("Could not translate 0x%0.8X to any environment variables", Hash);
	return FALSE;
}

HMODULE LoadDllFromSystem32ByHash(IN DWORD Hash) {

	WIN32_FIND_DATAA FileData = { 0 };
	HANDLE hFile;
	CHAR DirSearchString[MAX_PATH];
	BOOL System32Found = FALSE;

	LOCATE_KERNEL32_FUNCTION(LoadLibraryA);
	LOCATE_KERNEL32_FUNCTION(FindFirstFileA);
	LOCATE_KERNEL32_FUNCTION(FindNextFileA);

	SIZE_T VarSize = GetEnvVarByHash(hc_WINDIR, DirSearchString);
	if (VarSize == 0 || VarSize > MAX_PATH)
		return NULL;
	StringConcatA(DirSearchString, "\\*");

	if ((hFile = FindFirstFileA_(DirSearchString, &FileData)) == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	do
	{
		if (HashString(FileData.cFileName) == hc_SYSTEM32)
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
			hc_dbg("Resolved 0x%0.8X to %s", Hash, FileData.cFileName);
			return LoadLibraryA_(FileData.cFileName);
		}
	} while (FindNextFileA_(hFile, &FileData) != 0);

	hc_dbg("Could not resolve 0x%0.8X to any dll in system32", Hash);
	return NULL;
}

BOOL InitApiCalls() {
	PAPI_CALL pApiCall = (PAPI_CALL)&HashedAPI;

	hc_dbg("Beginning hashed API resolution...");

	if (!(&HashedAPI)->Initialized) {
		for (int i = 0; i < (sizeof(API_CALL_LIST) / sizeof(API_CALL)); i++) {
			hc_dbg("Resolving function %i of %zu [Function: 0x%0.8X, Dll: 0x%0.8X]", (i + 1), (sizeof(API_CALL_LIST) / sizeof(API_CALL)), pApiCall->Hash, pApiCall->ModuleHash);
			if ((pApiCall->hModule = GetModuleHandleByHash(pApiCall->ModuleHash)) == NULL) {
				hc_dbg("No module was found. Loading module from c:\\windows\\system32...");
				if ((pApiCall->hModule = LoadDllFromSystem32ByHash(pApiCall->ModuleHash)) == NULL) {
					hc_dbg("Could not find dll file in system32 matching hash 0x%0.8X", pApiCall->ModuleHash);
					return FALSE;
				}
			}
			if ((pApiCall->Address = GetProcAddressByHash(pApiCall->hModule, pApiCall->Hash)) == NULL) {
				hc_dbg("Could not find a function address for the hash 0x%0.8X", pApiCall->Hash);
				return FALSE;
			}
			(ULONG_PTR)pApiCall += sizeof(API_CALL);
		}
		(&HashedAPI)->Initialized = TRUE;
	}
	return TRUE;
}

