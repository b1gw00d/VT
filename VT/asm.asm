


.CODE 
extern GetGRegister:near
extern  VMMertry:near


VMMEntry PROC
	cli
	push rax
	push rcx
	push rdx
	push rbx
	push rbp
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14 
	push r15
	call GetGRegister
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	pop rdx
	pop rcx

	mov [rax+8h],rcx
	mov [rax+10h],rdx
	mov [rax+18h],rbx
	mov [rax+20h],rbp
	mov [rax+28h],rsi
	mov [rax+30h],rdi
	mov [rax+38h],r8
	mov [rax+40h],r9
	mov [rax+48h],r10
	mov [rax+50h],r11
	mov [rax+58h],r12
	mov [rax+60h],r13
	mov [rax+68h],r14
	mov [rax+70h],r15

	
	mov rcx,rax
	pop rax
	mov [rcx],rax
	mov rcx,[rcx+78h];i
	call VMMertry
	mov rcx,[rax+8h]
	mov rdx,[rax+10h]
	mov rbx,[rax+18h]
	mov rbp,[rax+20h]
	mov rsi,[rax+28h]
	mov rdi,[rax+30h]
	mov r8,[rax+38h]
	mov r9,[rax+40h]
	mov r10,[rax+48h]
	mov r11,[rax+50h]
	mov r12,[rax+58h]
	mov r13,[rax+60h]
	mov r14,[rax+68h]
	mov r15,[rax+70h]
	mov rax,[rax]
	sti
	vmresume
VMMEntry ENDP




__invd PROC
    invd
    ret
__invd ENDP


asmsgdt PROC
	sgdt [rcx]
	ret
asmsgdt ENDP

__Ds PROC
	sub rax,rax
	mov rax,es
	ret
__Ds ENDP
__Es PROC
	sub rax,rax
	mov rax,es
	ret
__Es ENDP


__Cs PROC
	sub rax,rax
	mov rax,cs
	ret
__Cs ENDP

__Ss PROC
	sub rax,rax
	mov rax,Ss
	ret
__Ss ENDP


__Fs PROC
	sub rax,rax
	mov rax,Fs
	ret
__Fs ENDP

__Gs PROC
	sub rax,rax
	mov rax,gs
	ret
__Gs ENDP

__Ldtr PROC
	sldt	rax
	ret
__Ldtr ENDP

__Tr PROC
	str	rax
	ret
__Tr ENDP


__writecr2 PROC
	mov cr2, rcx
	ret
__writecr2 ENDP



__launchAddReturn PROC
	mov rax,[rsp]
	mov rcx,rsp
	add rcx,8h
	mov r8,681ch;rsp
	mov r9,681eh;rip
	vmwrite r8,rcx
	vmwrite r9,rax
	vmlaunch
	ret
__launchAddReturn ENDP

__launch PROC
	push rax
	push rcx
	push rdx
	push rbx
	push rbp
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14 
	push r15
	call __launchAddReturn
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	pop rdx
	pop rcx
	pop rax
	ret
__launch ENDP



__saveRegister PROC
	push rax
	push rcx
	push rdx
	push rbx
	push rbp
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14 
	push r15
	ret
__saveRegister ENDP


__reductionRegister PROC
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	pop rdx
	pop rcx
	pop rax
	ret
__reductionRegister ENDP

END  