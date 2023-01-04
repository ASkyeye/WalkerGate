.data
	SyscallID DWORD 0

.code 
	SetSyscall PROC
		mov SyscallID, ecx
		ret
	SetSyscall ENDP

	CallSyscall PROC
		mov r10, rcx
		mov eax, SyscallID
		syscall
		ret

	CallSyscall ENDP
end
