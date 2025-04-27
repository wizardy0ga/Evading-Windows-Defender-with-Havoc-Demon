; Disabled as reflective dlls can't use global variables. Had to modify this code from hellshall to avoid global variables for reflective injection function.
;
; .data
;	pSyscall			QWORD   0h

.code

	; Sets pSyscall to pointer to SYSTEM_CALL structure pointer
	SetSyscallPointer proc
		xor rax, rax			; rax = 0
		; mov pSyscall, rcx		; move SYSTEM_CALL structure pointer to global variable
		mov rbx, rcx			; move to SYSTEM_CALL structure to non-volatile register instead to avoid global variable usage
		ret
	SetSyscallPointer endp

	; Resolve SSN & syscall instruction address from SYSTEM_CALL structure,
	; execute indirect system call
	SystemCall proc
		xor r11, r11			; r11 = 0
		;mov r11, pSyscall		
		mov r11, rbx			; r11 = pSyscall
		mov r10, rcx			; move parameters to r10 register
		mov eax, [r11]			; eax = pSyscall->SSN
		jmp qword ptr [r11 + 8] ; jump to syscall address @ pSyscall->JumpAddress
		ret
	SystemCall endp

end