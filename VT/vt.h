#pragma once
extern"C"
{
	//asm
	void __invd();
	void asmsgdt(PVOID);
	ULONG64 __Es();
	ULONG64 __Cs();
	ULONG64 __Ss();
	ULONG64 __Fs();
	ULONG64 __Gs();
	ULONG64 __Ldtr();
	ULONG64 __Tr();
	ULONG64 __Ds();
	void __launch();
	void __saveRegister();
	void __reductionRegister();
	void VMMEntry();
}


NTSTATUS chackCPUID();
NTSTATUS  VtAbility();
NTSTATUS VMXON(ULONG64 i);
NTSTATUS Stack(ULONG64 i);
NTSTATUS VMXCS(ULONG64 i);
NTSTATUS SetupVMCS(ULONG64 i);
NTSTATUS OpenBit();

ULONG32 getBit(ULONG32 bitSetOne, ULONG32 msr);
void getSegment(PSegment pSegment);
