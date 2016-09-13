

#include<ntddk.h>
#include"class.h"
#include<intrin.h>
#include"vt.h"
Register gRegister[64];
CPUaddress cpuAddress[64];
Register RegisterBuffer;
KMUTEX g_GlobalMutex;
extern"C" ULONGLONG GetGRegisterBuffer()
{
	return (ULONGLONG)&RegisterBuffer;
}
extern"C" ULONGLONG GetGRegister()
{

	ULONG i=KeGetCurrentProcessorNumber();
	gRegister[i].Number = i;
	return (ULONGLONG)&gRegister[i];
}


FORCEINLINE size_t __readvmx(ULONG Type)
{
	size_t val = 0;
	__vmx_vmread(Type, &val);

	return val;
}

NTSTATUS SupportVT()
{
	int iCPUID[4];
	__cpuid(iCPUID, 1);
	CPUIDrcx *rcx = (CPUIDrcx *)&(iCPUID[2]);
	if (!rcx->VMX==1)
	{
		return STATUS_UNSUCCESSFUL;//cpu不支持
	}

	return STATUS_SUCCESS;
}

NTSTATUS  VtAbility()
{
	//_VMX_BASIC_MSR msr = { 0 };
	ULONGLONG msr;
	msr = __readmsr(MSR_IA32_VMX_BASIC);
	if (((PVMX_BASIC_MSR)&msr)->useTrue == 1)
	{
		MSR_IA32_VMX_PINBASED_CTLS = 0x48D;//#define IA32_VMX_TRUE_PINBASED_CTLS 0x48D
		MSR_IA32_VMX_PROCBASED_CTLS = 0x48E;//#define IA32_VMX_TRUE_PROCBASED_CTLS 0x48E
		MSR_IA32_VMX_EXIT_CTLS = 0x48F;//#define IA32_VMX_TRUE_EXIT_CTLS 0x48F
		MSR_IA32_VMX_ENTRY_CTLS = 0x490;//#define IA32_VMX_TRUE_ENTRY_CTLS 0x490

	}
	msr = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);
	if ((msr >> 63) == 0) 
	{ 
		return STATUS_UNSUCCESSFUL;//bit 63==1  support IA32_VMX_PROCBASED_CTLS2
	}
	msr = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	if ((msr << 30 >> 63) == 0)
	{
		return STATUS_UNSUCCESSFUL;//bit33 ==1 supportt IA32_VMX_EPT_VPID_CAP
	}
	if ((msr << 18 >> 63) == 0)
	{
		return STATUS_UNSUCCESSFUL; //bit45==1 support IA32_VMX_VMFUNC
	}
	
	
	return STATUS_SUCCESS;

}
NTSTATUS OpenBit()
{

	ULONGLONG rcr0, rcr4;
	PCR0 pcr0;
	PCR4 pcr4;
	rcr0 = __readcr0();
	rcr4 = __readcr4();
	pcr0 = (PCR0)&rcr0;
	pcr4 = (PCR4)&rcr4;
	if (!(pcr0->PE==1) && (pcr0->PG==1) && (pcr0->NE==1))
	{
		return STATUS_UNSUCCESSFUL;
	}
	if ((pcr4->VMXE==1))
	{
		return STATUS_UNSUCCESSFUL;//别人开了
	}
	__int64 msr = __readmsr(MSR_IA32_FEATURE_CONTROL);
	if (!(msr && 1))
	{
		//vt被关闭
		return STATUS_UNSUCCESSFUL;
	}
	msr = msr | 7;
	__writemsr(MSR_IA32_FEATURE_CONTROL, msr);
	__writecr4(__readcr4() | (1 << 13));
	return STATUS_SUCCESS;
}



void HandleCPUID(ULONGLONG i)
{


	unsigned int iCPUID[4];
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

void HandleInvd(ULONGLONG i)
{
	__invd();
}

void HandleVmCall(ULONGLONG I)
{	
	DbgBreakPoint();
	//需要肛
}

void HandleMsrRead(ULONGLONG i)
{

	switch (gRegister[i].rcx)
	{
	case MSR_IA32_SYSENTER_CS:
		 __vmx_vmread(GUEST_SYSENTER_CS, &gRegister[i].rax);
		gRegister[i].rdx = gRegister[i].rax >> 32;
		gRegister[i].rax &= 0xFFFFFFFF;

		break;
	case MSR_IA32_SYSENTER_ESP:
		 __vmx_vmread(GUEST_SYSENTER_ESP, &gRegister[i].rax);
		gRegister[i].rdx = gRegister[i].rax >> 32;
		gRegister[i].rax &= 0xFFFFFFFF;
		break;
	case MSR_IA32_SYSENTER_EIP:
		__vmx_vmread(GUEST_SYSENTER_EIP, &gRegister[i].rax);
		gRegister[i].rdx = gRegister[i].rax >> 32;
		gRegister[i].rax &= 0xFFFFFFFF;
		break;
	case MSR_GS_BASE:
		__vmx_vmread(GUEST_GS_BASE, &gRegister[i].rax);
		gRegister[i].rdx = gRegister[i].rax >> 32;
		gRegister[i].rax &= 0xFFFFFFFF;
		break;
	case MSR_FS_BASE:
		__vmx_vmread(GUEST_FS_BASE, &gRegister[i].rax);
		gRegister[i].rdx = gRegister[i].rax >> 32;
		gRegister[i].rax &= 0xFFFFFFFF;
		break;
	case MSR_EFER:
		gRegister[i].rax = __readmsr(MSR_EFER);
		gRegister[i].rdx = gRegister[i].rax >>32;
		gRegister[i].rax &= 0xFFFFFFFF;
		break;

	default:
		gRegister[i].rax = __readmsr(gRegister[i].rcx);
		gRegister[i].rdx = gRegister[i].rax >> 32;
		gRegister[i].rax &= 0xFFFFFFFF;
		break;
	}
}
void HandleMsrWrite(ULONGLONG i)
{

	switch (gRegister[i].rcx)
	{
	case MSR_IA32_SYSENTER_CS:
		__vmx_vmwrite(GUEST_SYSENTER_CS, (gRegister[i].rax& 0xFFFFFFFF) | (gRegister[i].rdx << 32));
		break;
	case MSR_IA32_SYSENTER_ESP:
		__vmx_vmwrite(GUEST_SYSENTER_ESP, (gRegister[i].rax & 0xFFFFFFFF) | (gRegister[i].rdx << 32));
		break;
	case MSR_IA32_SYSENTER_EIP:
		__vmx_vmwrite(GUEST_SYSENTER_EIP, (gRegister[i].rax & 0xFFFFFFFF) | (gRegister[i].rdx << 32));
		break;
	case MSR_GS_BASE:
		__vmx_vmwrite(GUEST_GS_BASE, (gRegister[i].rax & 0xFFFFFFFF) | (gRegister[i].rdx << 32));
		break;
	case MSR_FS_BASE:
		__vmx_vmwrite(GUEST_FS_BASE, (gRegister[i].rax & 0xFFFFFFFF) | (gRegister[i].rdx << 32));
		break;
	case MSR_EFER:
		__writemsr(MSR_EFER, (gRegister[i].rax & 0xFFFFFFFF) | (gRegister[i].rdx << 32));
		break;
	default:
		__writemsr(gRegister[i].rcx, (gRegister[i].rax & 0xFFFFFFFF) |(gRegister[i].rdx<<32));
		break;
	}
}
void HandleCrAccress(ULONGLONG i)
{
	ExitQualificationCRn EQC = { 0 };
	ULONGLONG ubuffer64;

	__vmx_vmread(EXIT_QUALIFICATION, &ubuffer64);
	
	*(LONGLONG *)&EQC = ubuffer64;
	ULONGLONG *pregister = (ULONGLONG*)&(gRegister[i]);
	


	switch (EQC.AccessType)
	{
	case MovFromCr:
			switch (EQC.CRn)
			{
			case 0:
				__vmx_vmread(GUEST_CR0, &ubuffer64);
				pregister[EQC.GPR] = ubuffer64;
				break;
			case 3:
				__vmx_vmread(GUEST_CR3, &ubuffer64);
				pregister[EQC.GPR] = ubuffer64;
				break;
			case 4:
				__vmx_vmread(GUEST_CR4, &ubuffer64);
				pregister[EQC.GPR] = ubuffer64;
				break;
			default:
				break;
			}

		break;

	case MovToCr:
			switch (EQC.CRn)
			{
			case 0:
				__vmx_vmwrite(GUEST_CR0, pregister[EQC.GPR]);
				break;
			case 3:
				__vmx_vmwrite(GUEST_CR3, pregister[EQC.GPR]);
				break;
			case 4:
				__vmx_vmwrite(GUEST_CR4, pregister[EQC.GPR]);
				break;
			default:
				break;
			}


		break;

	case CLTSoperator:
		//TS bit3;

		__vmx_vmread(GUEST_CR0, &ubuffer64);
		ubuffer64 &= 0xFFFFFFFFFFFFFFF7;
		break;

	case LMSWoperator:
		DbgBreakPoint();
		break;
	default:
		DbgBreakPoint();
		break;
	}
	


}

NTSTATUS Stack(int i)
{
	cpuAddress[i].pStack = ExAllocatePoolWithTag(NonPagedPool, 0x4000, (ULONG)"STVMX" + i);
	RtlZeroMemory(cpuAddress[i].pStack, 0x4000);
	cpuAddress[i].pStack = (PVOID)((ULONGLONG)cpuAddress[i].pStack + 0x2000);
	cpuAddress[i].phStack = MmGetPhysicalAddress(cpuAddress[i].pStack);
	return STATUS_SUCCESS;
}

NTSTATUS OpenVT()
{
	NTSTATUS issuccess;
	if (!NT_SUCCESS(SupportVT()))
	{
		return STATUS_UNSUCCESSFUL;
	}
	KAFFINITY nAffinity = KeQueryActiveProcessors(), nCurrent;
	NTSTATUS status;
	KIRQL OldIrql;
	VtAbility();

	KeInitializeMutex(&g_GlobalMutex, 0);
	issuccess=KeWaitForMutexObject(&g_GlobalMutex, Executive, KernelMode, FALSE, 0);
	for (int i = 0; i < 64; ++i)
	{
		unsigned __int64 bitActiveprocess = ((nAffinity << (63 - i)) >> 63);
		if (bitActiveprocess != 0)
		{
			DbgBreakPoint();
			KeSetSystemAffinityThreadEx((KAFFINITY)1<<i);
			DbgBreakPoint();
			OldIrql = KeRaiseIrqlToDpcLevel();
			DbgBreakPoint();
			OpenBit();
			VMXON(i);
			Stack(i);
			__VMXCS(i);
			KeLowerIrql(0);
			KeRevertToUserAffinityThread();
			
			
		}
	}

	KeReleaseMutex(&g_GlobalMutex, FALSE);
	DbgBreakPoint();
	return STATUS_SUCCESS;
}



extern"C" ULONGLONG VMMertry(ULONGLONG i)
{

	ULONG64 ExitReason,exitError;
	SIZE_T instructionLen;
	__vmx_vmread(VM_EXIT_INTR_ERROR_CODE, &exitError);
	__vmx_vmread(VM_EXIT_REASON, &ExitReason);
	__vmx_vmread(GUEST_RIP, &gRegister[i].rip);
	__vmx_vmread(GUEST_RSP, &gRegister[i].rsp);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &instructionLen);

	//DbgBreakPoint();

	switch (ExitReason)
	{
	case EXIT_REASON_EXCEPTION_NMI:
		switch (exitError)
		{
			/*case 4:
				__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);
				break;
			default:
				DbgBreakPoint();*/
				break;
		}
		break;
	case EXIT_REASON_CPUID:
		HandleCPUID(i);
		gRegister[i].rip += instructionLen;
		break;
	case EXIT_REASON_VMCALL:
		HandleVmCall(i);
		gRegister[i].rip += instructionLen;
		break;
	case EXIT_REASON_INVD:
		HandleInvd(i);
		gRegister[i].rip += instructionLen;
		break;
	case EXIT_REASON_MSR_READ:
		HandleMsrRead(i);
		gRegister[i].rip += instructionLen;
		break;
	case EXIT_REASON_MSR_WRITE:
		HandleMsrWrite(i);
		gRegister[i].rip += instructionLen;
		break;
	case EXIT_REASON_CR_ACCESS:
		HandleCrAccress(i);
		gRegister[i].rip += instructionLen;
		break;
	case EXIT_REASON_RDTSCP:
		DbgBreakPoint();
		break;
	default:
		DbgBreakPoint();
		break;
	}





		
		 


	__vmx_vmwrite(GUEST_RIP, gRegister[i].rip);
	__vmx_vmwrite(GUEST_RSP, gRegister[i].rsp);
	//DbgBreakPoint();
	return (ULONGLONG)&gRegister[i];
}


NTSTATUS VMXON(int i)
{
	VMX_BASIC_MSR VmxBaseMsr = {0};
	*(ULONGLONG*)&VmxBaseMsr =__readmsr(MSR_IA32_VMX_BASIC);
	cpuAddress[i].pVMXON=ExAllocatePoolWithTag(NonPagedPool, 0x4000, (ULONG)"ONVMX"+i);
	cpuAddress[i].phVMXON = MmGetPhysicalAddress(cpuAddress[i].pVMXON);
	RtlZeroMemory(cpuAddress[i].pVMXON, 0x4000);
	*(ULONG*)cpuAddress[i].pVMXON = VmxBaseMsr.RevId;
	if (__vmx_on((ULONGLONG *)&(cpuAddress[i].phVMXON)) == 0)
	{
		return STATUS_SUCCESS;//成功
	}
	return STATUS_UNSUCCESSFUL;
}

extern"C" NTSTATUS VMXCS(ULONGLONG rip, ULONGLONG rsp,int i)
{

	/*-----------*/

	/*-----------*/

//用来确定VMXCS区域的大小 这里直接忽略
	VMX_BASIC_MSR VmxBaseMsr = { 0 };
	*(ULONGLONG*)&VmxBaseMsr = __readmsr(MSR_IA32_VMX_BASIC);
//END


	cpuAddress[i].pVMXCS = ExAllocatePoolWithTag(NonPagedPool, 0x4000, ULONG("CSVMX") + i);
	cpuAddress[i].phVMXCS = MmGetPhysicalAddress(cpuAddress[i].pVMXCS);

	RtlZeroMemory(cpuAddress[i].pVMXCS, 0x4000);

	*(ULONG *)cpuAddress[i].pVMXCS = VmxBaseMsr.RevId;//VMCS ID
	ULONGLONG IsError = 0, ErrorReason = 0;
	IsError=__vmx_vmclear((ULONGLONG *)&cpuAddress[i].phVMXCS);
	IsError=__vmx_vmptrld((ULONGLONG *)&cpuAddress[i].phVMXCS);



//全局变量
	ULONGLONG ubuffer64 = 0;
	ULONG ubuffer32 = 0;
	MsrTure msrture = { 0 };
//END

//execution

	//ping-basse VM-execution control
	ubuffer32 = 0;
	*(ULONGLONG *)&msrture = __readmsr(MSR_IA32_VMX_PINBASED_CTLS);
	ubuffer32 |= msrture.OneoSetOne;
	ubuffer32 &= msrture.ZeroSetZero;
	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, ubuffer32);//测试输出 10110;
	//end

	//processor-based VM-execution contral

		//primary processor-based VM-execution contral
		ubuffer32 = 0;
		*(ULONGLONG *)&msrture = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);
		ubuffer32 |= msrture.OneoSetOne;
		ubuffer32 &= msrture.ZeroSetZero;
		ubuffer32 |= (1 << 31);
		__vmx_vmwrite(Primary_processor_based_VM_execution_controls, ubuffer32); //测试输出  100000000000110000101110010
		//end

		//secondary-based VM-execution contral
		ubuffer32 = 0;
		*(ULONGLONG *)&msrture = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
		ubuffer32 |= msrture.OneoSetOne;
		ubuffer32 &= msrture.ZeroSetZero;
		ubuffer32 |= (1 << 3);
		ubuffer32 |= (1 << 12);
		__vmx_vmwrite(Secondary_processor_based_VM_execution_controls, ubuffer32);//测试输出 0
		 //end
	//end

	//exception bitmap
		__vmx_vmwrite(EXCEPTION_BITMAP, 0);
	
	//end

	//PFEC_MASK and PFEC_MATCH
		__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
		__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0/*1*/);//--------------

	//end

	// I/O bitmap address
		__vmx_vmwrite(IO_BITMAP_A_ADDRESS, 0);
		__vmx_vmwrite(IO_BITMAP_B_ADDRESS, 0);
	//end

	//TSC offset
		__vmx_vmwrite(TSC_OFFSET, 0);
	//end


	//guest/host mask
		__vmx_vmwrite(CR0_GUEST_HOST_MASK, 0);
		__vmx_vmwrite(CR4_GUEST_HOST_MASK, 0);
	//end

	//read shadow
		__vmx_vmwrite(CR0_READ_SHADOW, __readcr0());
		__vmx_vmwrite(CR4_READ_SHADOW, __readcr4());
	//end

	//CR3-target
		__vmx_vmwrite(CR3_TARGET_COUNT,0 );
		__vmx_vmwrite(CR3_TARGET_VALUE0, 0);
		__vmx_vmwrite(CR3_TARGET_VALUE1, 0);
		__vmx_vmwrite(CR3_TARGET_VALUE2, 0);
		__vmx_vmwrite(CR3_TARGET_VALUE3, 0);
	//end

	//APIC-access address
		__vmx_vmwrite(APIC_access_address, 0);
	//end

	//virtual-APIC address
		__vmx_vmwrite(virtual_APIC_address, 0);
	//end

	//TPR threshold
		__vmx_vmwrite(TPR_THRESHOLD, 0);
	//end

	//EOI-exit bitmap
		__vmx_vmwrite(EOI_EXIT_BITMAP0, 0);
		__vmx_vmwrite(EOI_EXIT_BITMAP1, 0);
		__vmx_vmwrite(EOI_EXIT_BITMAP2, 0);
		__vmx_vmwrite(EOI_EXIT_BITMAP3, 0);
	//end

	//poseed-interrupt notification vector
		__vmx_vmwrite(POSTED_INTR_NV, 0);
	//end

	//posted-interrupt descriptor address
		__vmx_vmwrite(POSTED_INTR_DESC_ADDR, 0);
	//end

	//MSR bitmap address
		__vmx_vmwrite(MSR_BITMAP_address, 0);
	//end

	//executive-VMCE pointer

	//end

	//EPTP

	//end

	//virtual-processor identifier

	//end

	//PLE_Gap and PLE_Window

	//end

	//VM-function control
		__vmx_vmwrite(VM_function_control, 0);
	//end

	//EPTP_list address


	//end

	//END

//VM-entry控制类字段
	//VM-entry control
		ubuffer32 = 0;
		*(ULONGLONG *)&msrture = __readmsr(MSR_IA32_VMX_ENTRY_CTLS);
		ubuffer32 |= msrture.OneoSetOne;
		ubuffer32 &= msrture.ZeroSetZero;
		ubuffer32 |= (1 << 9);//IA32-e mode guest
		ubuffer32 |= (1 << 15);
		__vmx_vmwrite(VM_ENTRY_CONTROLS, ubuffer32);//测试输出 1000111111011;
	//end

	//VM-entry MSR-load
		__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
		__vmx_vmwrite(VM_ENTRY_MSR_LOAD_ADDR, 0);
	//end

	//事件注入控制字段
	//VM-entry interruption information
		__vmx_vmwrite(VM_ENTRY_INTRRUPTION_INFORMATION_FIELD, 0);
	//end

	//VM_entry exception error code
		__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, 0);
	//end

	//VM-entry instruction length
		__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, 0);
	//end

	//end

	//END

//VM-exit control
	//VM-exit control
		ubuffer32 = 0;
		*(ULONGLONG *)&msrture = __readmsr(MSR_IA32_VMX_EXIT_CTLS);
		ubuffer32 |= msrture.OneoSetOne;
		ubuffer32 &= msrture.ZeroSetZero;
		ubuffer32 |= (1 << 9);//host address-space size   ia-32e
		ubuffer32 |= (1 << 20);//save ia32 EFER
		__vmx_vmwrite(VM_EXIT_CONTROLS, ubuffer32); //测试输出
	//end

	//MSR
		__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);//
		__vmx_vmwrite(VM_EXIT_MSR_STORE_ADDR, 0);//
		__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);//
		__vmx_vmwrite(VM_EXIT_MSR_LOAD_ADDR, 0);//

	//end

//END

//guest-state

	//cr0 cr3 cr4 dr7
		__vmx_vmwrite(GUEST_CR0, __readcr0());
		__vmx_vmwrite(GUEST_CR3, __readcr3());
		__vmx_vmwrite(GUEST_CR4, __readcr4());
		__vmx_vmwrite(GUEST_DR7, 0x400);
	//end

	//RSP RIP RFLAGS
		__vmx_vmwrite(GUEST_RSP, rsp);//
		__vmx_vmwrite(GUEST_RIP, rip);//
		__vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	//end

	//Segment   ????
		Segment segment;
		getSegment(&segment);
		__vmx_vmwrite(GUEST_ES_BASE, 0);
		__vmx_vmwrite(GUEST_CS_BASE, 0);
		__vmx_vmwrite(GUEST_SS_BASE, 0);
		__vmx_vmwrite(GUEST_DS_BASE, 0);
		__vmx_vmwrite(GUEST_LDTR_BASE, segment.ldtr.Base);
		__vmx_vmwrite(GUEST_TR_BASE, segment.tr.Base);
		ubuffer64= __readmsr(MSR_GS_BASE);
		__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));//ok
		__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));//ok


		__vmx_vmwrite(GUEST_ES_SELECTOR, segment.es.Selector);
		__vmx_vmwrite(GUEST_CS_SELECTOR, segment.cs.Selector);
		__vmx_vmwrite(GUEST_SS_SELECTOR, segment.ss.Selector);
		__vmx_vmwrite(GUEST_DS_SELECTOR, segment.ds.Selector);
		__vmx_vmwrite(GUEST_FS_SELECTOR, segment.fs.Selector);
		__vmx_vmwrite(GUEST_GS_SELECTOR, segment.gs.Selector);
		__vmx_vmwrite(GUEST_LDTR_SELECTOR, segment.ldtr.Selector);
		__vmx_vmwrite(GUEST_TR_SELECTOR, segment.tr.Selector);

		__vmx_vmwrite(GUEST_ES_LIMIT, segment.es.Limit);
		__vmx_vmwrite(GUEST_CS_LIMIT, segment.cs.Limit);
		__vmx_vmwrite(GUEST_SS_LIMIT, segment.ss.Limit);
		__vmx_vmwrite(GUEST_DS_LIMIT, segment.ds.Limit);
		__vmx_vmwrite(GUEST_FS_LIMIT, segment.fs.Limit);
		__vmx_vmwrite(GUEST_GS_LIMIT, segment.gs.Limit);
		__vmx_vmwrite(GUEST_LDTR_LIMIT, segment.ldtr.Limit);
		__vmx_vmwrite(GUEST_TR_LIMIT, segment.tr.Limit);

		__vmx_vmwrite(GUEST_ES_AR_BYTES, segment.es.AccessRights);
		__vmx_vmwrite(GUEST_CS_AR_BYTES, segment.cs.AccessRights);
		__vmx_vmwrite(GUEST_SS_AR_BYTES, segment.ss.AccessRights);
		__vmx_vmwrite(GUEST_DS_AR_BYTES, segment.ds.AccessRights);
		__vmx_vmwrite(GUEST_FS_AR_BYTES, segment.fs.AccessRights);
		__vmx_vmwrite(GUEST_GS_AR_BYTES, segment.gs.AccessRights);
		__vmx_vmwrite(GUEST_LDTR_AR_BYTES, 0x10000);
		__vmx_vmwrite(GUEST_TR_AR_BYTES, segment.tr.AccessRights);

		Gdtr gdtr = { 0 };
		asmsgdt(&gdtr);
		__vmx_vmwrite(GUEST_GDTR_BASE, gdtr.gaddress);
		__vmx_vmwrite(GUEST_GDTR_LIMIT, gdtr.limit);
		IDTR idtr = { 0 };
		__sidt(&idtr);
		__vmx_vmwrite(GUEST_IDTR_BASE, (size_t)idtr.Base);
		__vmx_vmwrite(GUEST_IDTR_LIMIT, idtr.Limit);

	//end

	//MSR
		//IA32_DEBUGCTL
			__vmx_vmwrite(GUEST_IA32_DEBUGCTL, MsrRead(MSR_IA32_DEBUGCTL) );
		//end

		//IA32_SYSENTER_CS
			__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
		//end

		//IA32_SYSENTER_RSP
			__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
		//end

		//IA32_SYSENTER_RIP
			__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_ESP));
		//end

		//IA32_PERF_GLOBAL_CTRL

		//end

		//IA32_PAT

		//end

		//IA32_EFER
			__vmx_vmwrite(GUEST_IA32_EFER, __readmsr(MSR_EFER));//ok
		//end

	//end

	//SMBASE

	//end

	//activity state
		__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);
	//end

	//interruptibility state
		__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	//end

	//pending debug exceptions
	//????
	//end

	//VMCS link pointer
		__vmx_vmwrite(VMCS_LINK_POINTER, 0XFFFFFFFFFFFFFFFF);

	//end

	//VMX-preemption timer value
		__vmx_vmwrite(VMX_PREEMPTION_TIMER_VALUE, 0);
	//end

	//PDPTEs

	//end

	//guest interrupt status

	//end

//END

//host-state
	//CR0 CR3 CR4
		__vmx_vmwrite(HOST_CR0, __readcr0());
		__vmx_vmwrite(HOST_CR3, __readcr3());
		__vmx_vmwrite(HOST_CR4, __readcr4());
	//end

	//RSP RIP
		__vmx_vmwrite(HOST_RSP, (SIZE_T)cpuAddress[i].pStack);
		__vmx_vmwrite(HOST_RIP, (SIZE_T)&VMMEntry);
	//end

	//segment
		__vmx_vmwrite(HOST_ES_SELECTOR, KGDT64_R0_DATA);
		__vmx_vmwrite(HOST_CS_SELECTOR, KGDT64_R0_CODE);
		__vmx_vmwrite(HOST_SS_SELECTOR, KGDT64_R0_DATA);
		__vmx_vmwrite(HOST_DS_SELECTOR, KGDT64_R0_DATA);
		__vmx_vmwrite(HOST_FS_SELECTOR, __Fs()&0xF8);//ok
		__vmx_vmwrite(HOST_GS_SELECTOR, __Gs()&0xF8);//ok
		__vmx_vmwrite(HOST_TR_SELECTOR, __Tr() & 0xF8);//ok
		__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
		__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));
		__vmx_vmwrite(HOST_TR_BASE, segment.tr.Base);
		


		__vmx_vmwrite(HOST_GDTR_BASE, gdtr.gaddress);
		__vmx_vmwrite(HOST_IDTR_BASE, (size_t)idtr.Base);
		__vmx_vmwrite(HOST_TR_BASE, segment.tr.Base);
		__vmx_vmwrite(HOST_IA32_EFER, __readmsr(MSR_EFER));

	//end

	//MSR
		__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
		__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
		__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	//end



//END





	__vmx_vmlaunch();
	//DbgBreakPoint();
	//__vmx_vmread(VM_INSTRUCTION_ERROR, &adw);
	return STATUS_SUCCESS;
}


void getSegmentInfornation(pSegmentPort pSegment, USHORT Selector)
{

	pSegment->Selector = Selector;
	Gdtr gdtr = {0};
	asmsgdt(&gdtr);
	Selector = (Selector >> 3);
	GDTdescriptor gdt;
	gdt = *(PGDTdescriptor)(Selector * 8 + gdtr.gaddress);
	pSegment->AccessRights = ((*(ULONGLONG*)(&gdt)) >> 40) & 0x1F0FF;//11111000011111111
	pSegment->Base = gdt.Address1 | (gdt.Address2 << 16) | (gdt.Adddress3 << 24);
//	if ((gdt.Type<<1) >> 3 == 0)//上延伸段
//	{
		if (gdt.G == 0)
		{
			pSegment->Limit = gdt.SegmentLimit + (gdt.SegLimit << 16);
		}
		else
		{
			if (gdt.SegmentLimit == 0 && gdt.SegLimit == 0)
			{

				pSegment->Limit = 0;
			}
			else
			{
				pSegment->Limit = (gdt.SegmentLimit + (gdt.SegLimit << 16) + 1) * 0x4000 - 1;

			}
		}

	/*}
	else//下延伸段
	{
		ULONGLONG endaddress;
		if (gdt.DB==0)
		{
			endaddress = 0xffff;
		}
		else
		{
			endaddress = 0xffffffff;
		}
		if (gdt.G == 0)
		{
			pSegment->Limit = gdt.SegmentLimit + (gdt.SegLimit << 16);
		}
		else
		{
			if (gdt.SegmentLimit == 0 && gdt.SegLimit == 0)
			{
				DbgBreakPoint();
				pSegment->Limit = 0;
			}
			else
			{
				pSegment->Limit = (gdt.SegmentLimit + (gdt.SegLimit << 16) + 1) * 0x4000 - 1;
			}
			
		}
		//pSegment->Limit = endaddress-pSegment->Limit;
	}*/
}

void getSegment(PSegment pSegment)
{
	getSegmentInfornation(&(pSegment->cs), __Cs());
	getSegmentInfornation(&(pSegment->es), __Es());
	getSegmentInfornation(&(pSegment->ss), __Ss());
	getSegmentInfornation(&(pSegment->ds), __Ds());

	getSegmentInfornation(&(pSegment->gs), __Gs());

	getSegmentInfornation(&(pSegment->fs), __Fs());
	getSegmentInfornation(&(pSegment->tr), __Tr());
	getSegmentInfornation(&(pSegment->ldtr), __Ldtr());
}

