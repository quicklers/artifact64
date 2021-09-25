.data
	wSystemCall DWORD 000h

.code 
	Allocate PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx
		ret
	Allocate ENDP

	RunAllocated PROC
		mov r10, rcx
		mov eax, wSystemCall
		 
		syscall
		ret
	RunAllocated ENDP

	NtWriteVirtualMemory PROC
			add rcx, 0Bh
			xor eax, eax
			mov r10, rcx
				add eax, 3Ah		; 1507+
			sub r10, 0Bh
			sub rcx, 0Bh
			syscall
			ret
	NtWriteVirtualMemory ENDP

end