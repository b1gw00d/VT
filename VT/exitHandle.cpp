#include<ntddk.h>
#include<intrin.h>

#include"commom.h"
#include"class.h"
#include"exitHandle.h"
extern Register gRegister[64];

void HandleCPUID(ULONG64 i)
{


	int iCPUID[4];
	__cpuidex((int *)iCPUID, gRegister[i].rax, gRegister[i].rcx);
	if (gRegister[i].rax == 88888888)
	{
		iCPUID[0] = 88888888;
	}
	gRegister[i].rax = iCPUID[0];
	gRegister[i].rbx = iCPUID[1];
	gRegister[i].rcx = iCPUID[2];
	gRegister[i].rdx = iCPUID[3];

}

void HandleVmCall(ULONG64 I)
{
	DbgBreakPoint();
	//ÐèÒª¸Ø
}
void HandleInvd(ULONG64 i)
{
	__invd();
}


void HandleMsrRead(ULONG64 i)
{
	ULONG ecx = (ULONG)gRegister[i].rcx;
	ULONG64 ubuffer64;
	switch (ecx)
	{
	case MSR_IA32_SYSENTER_CS:
		__vmx_vmread(GUEST_SYSENTER_CS,&ubuffer64);
		break;
	case MSR_IA32_SYSENTER_ESP:
		__vmx_vmread(GUEST_SYSENTER_ESP, &ubuffer64);
		break;
	case MSR_IA32_SYSENTER_EIP:
		__vmx_vmread(GUEST_SYSENTER_EIP, &ubuffer64);
		break;
	case MSR_GS_BASE:
		__vmx_vmread(GUEST_GS_BASE, &ubuffer64);
		break;
	case MSR_FS_BASE:
		__vmx_vmread(GUEST_FS_BASE, &ubuffer64);
		break;
	default:
		ubuffer64 = __readmsr(ecx);
		break;
	}
	LARGE_INTEGER msr =* (LARGE_INTEGER*)&ubuffer64;
	gRegister[i].rax = msr.LowPart;
	gRegister[i].rdx = msr.HighPart;
}


void HandleMsrWrite(ULONG64 i)
{
	ULONG ecx = (ULONG)gRegister[i].rcx;
	ULONG64 rax = gRegister[i].rax & 0xFFFFFFFF;
	ULONG64 rdx = gRegister[i].rdx << 32;
	ULONG64 amsr = rdx | rax;
	switch (ecx)
	{
	case MSR_IA32_SYSENTER_CS:
		__vmx_vmwrite(GUEST_SYSENTER_CS, amsr);
		break;
	case MSR_IA32_SYSENTER_ESP:
		__vmx_vmwrite(GUEST_SYSENTER_ESP, amsr);
		break;
	case MSR_IA32_SYSENTER_EIP:
		__vmx_vmwrite(GUEST_SYSENTER_EIP, amsr);
		break;
	case MSR_GS_BASE:
		__vmx_vmwrite(GUEST_GS_BASE, amsr);
		break;
	case MSR_FS_BASE:
		__vmx_vmwrite(GUEST_FS_BASE, amsr);
		break;
	default:
		__writemsr(ecx, amsr);
		break;
	}
}
void HandleCrAccress(ULONG64 i)
{
	ExitQualificationCRn EQC = { 0 };
	ULONG64 ubuffer64;

	__vmx_vmread(EXIT_QUALIFICATION, &ubuffer64);

	*(LONG64 *)&EQC = ubuffer64;
	ULONG64 *pregister = (ULONG64*)&(gRegister[i]);
	if (EQC.GPR > 4)
	{
		EQC.GPR -= 1;
	}
	else
	{
		if (EQC.GPR == 4)
		{
			EQC.GPR = 17;
		}
	}
	Crx(EQC.AccessType, EQC.GPR, EQC.CRn, ubuffer64, pregister);
	

}

void HandleRdtscp(ULONG64 i)
{
	LARGE_INTEGER tsc;
	UINT32 procId;
	tsc.QuadPart = __rdtscp(&procId);
	gRegister[i].rax = tsc.LowPart;
	gRegister[i].rdx = tsc.HighPart;
	gRegister[i].rcx = procId;



}

void HandleRdtsc(ULONG64 i)
{
	LARGE_INTEGER tsc;
	tsc.QuadPart = __rdtsc();
	gRegister[i].rax = tsc.LowPart;
	gRegister[i].rdx = tsc.HighPart;
}


void HandleEXIT_REASON_EXCEPTION_NMI(ULONG64 i)
{
	ULONG64 ubuffer64;


	__vmx_vmread(VM_EXIT_INTR_INFO, &ubuffer64);
	INTERRUPT_INFO_FIELD interruptionInformation;
	*(ULONG*)&interruptionInformation = (ULONG)ubuffer64;

	__vmx_vmread(VM_EXIT_INTR_ERROR_CODE, &ubuffer64);
	ULONG interruptionErrorCode = (ULONG)ubuffer64;

	__vmx_vmread(IDT_VECTORING_INFO_FIELD, &ubuffer64);
	INTERRUPT_INJECT_INFO_FIELD IDT_VectoringInformationField;
	*(ULONG*)&IDT_VectoringInformationField = (ULONG)ubuffer64;

	__vmx_vmread(IDT_VECTORING_ERROR_CODE, &ubuffer64);
	ULONG IDT_EctoringErrorCode = (ULONG)ubuffer64;


	if (interruptionInformation.Valid==1)
	{
		__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, gRegister[i].exitError);
		switch (interruptionInformation.InterruptionType)
		{
		case INTERRUPT_NMI:
			VmInjectInterrupt(INTERRUPT_NMI, VECTOR_NMI_INTERRUPT, 0);
			break;
		case INTERRUPT_HARDWARE_EXCEPTION:
			switch (interruptionInformation.Vector)
			{
			case VECTOR_DEBUG_EXCEPTION://int 1
				VmInjectInterrupt(interruptionInformation.InterruptionType, interruptionInformation.Vector, gRegister[i].instructionLen);
				break;
			case VECTOR_INVALID_OPCODE_EXCEPTION:
				VmInjectInterrupt(interruptionInformation.InterruptionType, interruptionInformation.Vector, gRegister[i].instructionLen);
				break;
			case VECTOR_PAGE_FAULT_EXCEPTION:
				ubuffer64 = 0;
				__vmx_vmread(EXIT_QUALIFICATION, &ubuffer64);
				__writecr2(ubuffer64);
				VmInjectInterrupt(interruptionInformation.InterruptionType, interruptionInformation.Vector, gRegister[i].instructionLen);
				break;
			default:
				break;
			}

			break;
		default:
			DbgBreakPoint();
			break;
		}
	}
	if (IDT_VectoringInformationField.Valid == 1)
	{
		switch (IDT_VectoringInformationField.InterruptionType)
		{
		case INTERRUPT_NMI:
			VmInjectInterrupt(INTERRUPT_NMI, VECTOR_NMI_INTERRUPT, 0);
			break;
		default:
			DbgBreakPoint();
			break;
		}
	}



}

extern"C" ULONGLONG VMMertry(ULONGLONG i)
{
	__vmx_vmread(VM_EXIT_INTR_ERROR_CODE, &gRegister[i].exitError);
	__vmx_vmread(VM_EXIT_REASON, &gRegister[i].ExitReason);
	__vmx_vmread(GUEST_RIP, &gRegister[i].rip);
	__vmx_vmread(GUEST_RSP, &gRegister[i].rsp);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &gRegister[i].instructionLen);
	switch (gRegister[i].ExitReason)
	{
	case EXIT_REASON_EXCEPTION_NMI:
		HandleEXIT_REASON_EXCEPTION_NMI(i);
		break;
	case EXIT_REASON_CPUID:
		HandleCPUID(i);
		break;
	case EXIT_REASON_VMCALL:
		HandleVmCall(i);
		break;
	case EXIT_REASON_INVD:
		HandleInvd(i);
		break;
	case EXIT_REASON_MSR_READ:
		HandleMsrRead(i);
		break;
	case EXIT_REASON_MSR_WRITE:
		HandleMsrWrite(i);
		break;
	case EXIT_REASON_CR_ACCESS:
		HandleCrAccress(i);
		break;
	case EXIT_REASON_RDTSCP:
		HandleRdtscp(i);
		break;
	case EXIT_REASON_RDTSC:
		HandleRdtsc(i);
		break;
	default:
		DbgBreakPoint();
		break;
	}
	gRegister[i].rip += gRegister[i].instructionLen;

	__vmx_vmwrite(GUEST_RIP, gRegister[i].rip);
	__vmx_vmwrite(GUEST_RSP, gRegister[i].rsp);
	return (ULONGLONG)&gRegister[i];
}


void Crx(unsigned int type,unsigned int GPR,unsigned int crn, ULONG64 ubuffer64,ULONG64 *pregister)
{
	switch (type)
	{
	case MovFromCr:
		switch (crn)
		{
		case 0:
			__vmx_vmread(GUEST_CR0, &ubuffer64);
			pregister[GPR] = ubuffer64;
			break;
		case 3:
			__vmx_vmread(GUEST_CR3, &ubuffer64);
			pregister[GPR] = ubuffer64;
			break;
		case 4:
			__vmx_vmread(GUEST_CR4, &ubuffer64);
			pregister[GPR] = ubuffer64;
			break;
		default:
			break;
		}

		break;

	case MovToCr:
		switch (crn)
		{
		case 0:
			__vmx_vmwrite(GUEST_CR0, pregister[GPR]);
			break;
		case 3:
			__vmx_vmwrite(GUEST_CR3, pregister[GPR]);
			break;
		case 4:
			__vmx_vmwrite(GUEST_CR4, pregister[GPR]);
			break;
		default:
			break;
		}


		break;

	case CLTSoperator:
		ubuffer64 &= 0xFFFFFFFFFFFFFFF7;
		__vmx_vmread(GUEST_CR0, &ubuffer64);

		break;

	case LMSWoperator:
		DbgBreakPoint();
		break;
	default:
		DbgBreakPoint();
		break;
	}

}




void VmInjectInterrupt(ULONG InterruptType, ULONG Vector, SIZE_T WriteLength)
{

	ULONG InjectEvent = 0;
	PINTERRUPT_INJECT_INFO_FIELD pInjectEvent = (PINTERRUPT_INJECT_INFO_FIELD)&InjectEvent;

	pInjectEvent->Vector = Vector;
	pInjectEvent->InterruptionType = InterruptType;
	pInjectEvent->DeliverErrorCode = 0;
	pInjectEvent->Valid = 1;

	__vmx_vmwrite(VM_ENTRY_INTRRUPTION_INFORMATION_FIELD, InjectEvent);

	if (WriteLength > 0)
		__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, WriteLength);
}

