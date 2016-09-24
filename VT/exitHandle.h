#pragma once
extern"C"
{
	//asm
	void __invd();
	void __writecr2(SIZE_T);

}

void Crx(unsigned int type, unsigned int GPR, unsigned int crn, ULONG64 ubuffer64, ULONG64 *pregister);
void VmInjectInterrupt(ULONG InterruptType, ULONG Vector, SIZE_T WriteLength);