#include<ntddk.h>
#include<intrin.h>
#include"class.h"
#include"commom.h"
#include"vt.h"
CPUaddress cpuAddress[64] = {0};
Register gRegister[64] = { 0 }; 
KMUTEX g_GlobalMutex;

NTSTATUS OpenVT()
{

	KeInitializeMutex(&g_GlobalMutex, 0);
	KeWaitForMutexObject(&g_GlobalMutex, Executive, KernelMode, FALSE, 0);
	KAFFINITY nAffinity = KeQueryActiveProcessors();

	for (unsigned __int64  i = 0; i < 63; ++i)
	{
		ULONG64 fuck = 1;
		fuck = fuck << i;

		if ((nAffinity&fuck) != 0)
		{
			
			KeSetSystemAffinityThreadEx((KAFFINITY)fuck);
			KeRaiseIrqlToDpcLevel();
			if (chackCPUID()!= STATUS_SUCCESS)
			{
				DbgBreakPoint();
			}
			if (VtAbility() != STATUS_SUCCESS)
			{
				DbgBreakPoint();
			}
			if (OpenBit() != STATUS_SUCCESS)
			{
				DbgBreakPoint();
			}
			if (VMXON(i) != STATUS_SUCCESS)
			{
				DbgBreakPoint();
			}
			if (Stack(i) != STATUS_SUCCESS)
			{
				DbgBreakPoint();
			}
			if (VMXCS(i) != STATUS_SUCCESS)
			{
				DbgBreakPoint();
			}
			SetupVMCS(i);
			__launch();
			KeLowerIrql(0);
			KeRevertToUserAffinityThread();
		}

	}

	
	KeReleaseMutex(&g_GlobalMutex,FALSE);
	return STATUS_SUCCESS;
}

NTSTATUS chackCPUID()
{
	int iCPUID[4];
	__cpuid(iCPUID, 1);
	CPUIDrcx *rcx = (CPUIDrcx *)&(iCPUID[2]);
	if (!rcx->VMX == 1)
	{
		return STATUS_UNSUCCESSFUL;//cpu不支持
	}

	return STATUS_SUCCESS;
}

NTSTATUS  VtAbility()
{
	ULONGLONG msr;
	msr = __readmsr(MSR_IA32_VMX_BASIC);
	if (((PVMX_BASIC_MSR)&msr)->useTrue == 1)
	{
		//useTrue

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
	if (!(pcr0->PE == 1) && (pcr0->PG == 1) && (pcr0->NE == 1))
	{
		return STATUS_UNSUCCESSFUL;
	}
	if ((pcr4->VMXE == 1))
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


NTSTATUS VMXON(ULONG64 i)
{
	VMX_BASIC_MSR VmxBaseMsr = { 0 };
	*(ULONG64*)&VmxBaseMsr = __readmsr(MSR_IA32_VMX_BASIC);
	cpuAddress[i].pVMXON = ExAllocatePoolWithTag(NonPagedPool, 0x4000, ((ULONG)"ONVMX") + i);
	if (cpuAddress[i].pVMXON == NULL)
	{
		DbgBreakPoint();
	}
	cpuAddress[i].phVMXON = MmGetPhysicalAddress(cpuAddress[i].pVMXON);
	RtlZeroMemory(cpuAddress[i].pVMXON, 0x4000);
	*(ULONG*)cpuAddress[i].pVMXON = VmxBaseMsr.RevId;
	if (__vmx_on((ULONGLONG *)&(cpuAddress[i].phVMXON)) == 0)
	{
		return STATUS_SUCCESS;//成功
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS Stack(ULONG64 i)
{
	cpuAddress[i].pStack = ExAllocatePoolWithTag(NonPagedPool, 0x4000, ((ULONG)"STVMX") + i);
	if (cpuAddress[i].pStack == NULL)
	{
		DbgBreakPoint();
	}
	RtlZeroMemory(cpuAddress[i].pStack, 0x4000);
	cpuAddress[i].pStack = (PVOID)((ULONGLONG)cpuAddress[i].pStack + 0x2000);
	cpuAddress[i].phStack = MmGetPhysicalAddress(cpuAddress[i].pStack);
	return STATUS_SUCCESS;
}

NTSTATUS VMXCS(ULONG64 i)
{
	VMX_BASIC_MSR VmxBaseMsr = { 0 };
	*(ULONG64*)&VmxBaseMsr = __readmsr(MSR_IA32_VMX_BASIC);
	cpuAddress[i].pVMXCS=ExAllocatePoolWithTag(NonPagedPool, 0x4000, ((ULONG)"CSVMX") + i);
	if (cpuAddress[i].pVMXCS == NULL)
	{
		DbgBreakPoint();
	}
	cpuAddress[i].phVMXCS= MmGetPhysicalAddress(cpuAddress[i].pVMXCS);
	RtlZeroMemory(cpuAddress[i].pVMXCS, 0x4000);
	*(ULONG *)cpuAddress[i].pVMXCS = VmxBaseMsr.RevId;//VMCS ID
	__vmx_vmclear((ULONGLONG *)&cpuAddress[i].phVMXCS);
	__vmx_vmptrld((ULONGLONG *)&cpuAddress[i].phVMXCS);
	return STATUS_SUCCESS;
}

NTSTATUS SetupVMCS(ULONG64 i)
{
	Segment segment;
	getSegment(&segment);
	Gdtr gdtr = { 0 };
	asmsgdt(&gdtr);
	IDTR idtr = { 0 };
	__sidt(&idtr);

	//execution
	{
		__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, getBit(0, MSR_IA32_VMX_PINBASED_CTLS));                                            
		__vmx_vmwrite(Primary_processor_based_VM_execution_controls, getBit((1<<12)|(1<<31), MSR_IA32_VMX_PROCBASED_CTLS));			
		__vmx_vmwrite(Secondary_processor_based_VM_execution_controls, getBit((1<<3), MSR_IA32_VMX_PROCBASED_CTLS2));					
		__vmx_vmwrite(EXCEPTION_BITMAP, 0);																							
		__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);																					
		__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);																					
		//buffer64=__vmx_vmwrite(IO_BITMAP_A_ADDRESS, 0);																						
		//buffer64=__vmx_vmwrite(IO_BITMAP_B_ADDRESS, 0);																						

		//buffer64=__vmx_vmwrite(TSC_OFFSET, 0);																								
		__vmx_vmwrite(CR0_GUEST_HOST_MASK, 0);																							
		__vmx_vmwrite(CR4_GUEST_HOST_MASK, 0);																							
		__vmx_vmwrite(CR0_READ_SHADOW, 0);																								
		__vmx_vmwrite(CR4_READ_SHADOW, 0);																								
		__vmx_vmwrite(CR3_TARGET_COUNT, 0);																							
		__vmx_vmwrite(CR3_TARGET_VALUE0, 0);																							
		__vmx_vmwrite(CR3_TARGET_VALUE1, 0);																							
		__vmx_vmwrite(CR3_TARGET_VALUE2, 0);																							
		__vmx_vmwrite(CR3_TARGET_VALUE3, 0);																							
		//__vmx_vmwrite(APIC_access_address, 0);																						
		//buffer64=__vmx_vmwrite(virtual_APIC_address, 0);																				
		//buffer64=__vmx_vmwrite(TPR_THRESHOLD, 0);																						
		//buffer64=__vmx_vmwrite(EOI_EXIT_BITMAP0, 0);																					
		//buffer64=__vmx_vmwrite(EOI_EXIT_BITMAP1, 0);																					
		//buffer64=__vmx_vmwrite(EOI_EXIT_BITMAP2, 0);																					
		//buffer64=__vmx_vmwrite(EOI_EXIT_BITMAP3, 0);																					
		//buffer64=__vmx_vmwrite(POSTED_INTR_NV, 0);																					
		//buffer64=__vmx_vmwrite(POSTED_INTR_DESC_ADDR, 0);																				
		//buffer64=__vmx_vmwrite(MSR_BITMAP_address, 0);																				
		//buffer64=__vmx_vmwrite(VM_function_control, 0);																				
	}						
	//VM-entry控制类字段
	{
		__vmx_vmwrite(VM_ENTRY_CONTROLS, getBit(((1 << 9)|(1<<15) ), MSR_IA32_VMX_ENTRY_CTLS));										 
		__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);																						 
		//buffer64=__vmx_vmwrite(VM_ENTRY_MSR_LOAD_ADDR, 0);																					
		__vmx_vmwrite(VM_ENTRY_INTRRUPTION_INFORMATION_FIELD, 0);																		 
		__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, 0);																				 
		__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, 0);																					 
	}
	//VM-exit control
	{
		__vmx_vmwrite(VM_EXIT_CONTROLS, getBit(((1<<9)|(1<<20)), MSR_IA32_VMX_EXIT_CTLS));												 
		__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);																						 
		__vmx_vmwrite(VM_EXIT_MSR_STORE_ADDR, 0);																						 
		__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);																						 
		__vmx_vmwrite(VM_EXIT_MSR_LOAD_ADDR, 0);																						 
	}

	//guest-state
	{
		__vmx_vmwrite(GUEST_CR0, __readcr0());																							
		__vmx_vmwrite(GUEST_CR3, __readcr3());																							
		__vmx_vmwrite(GUEST_CR4, __readcr4());																							
		__vmx_vmwrite(GUEST_DR7, 0x400);																								
		__vmx_vmwrite(GUEST_RFLAGS, __readeflags());																					
		//rsp																																	
		//rip

		{

			__vmx_vmwrite(GUEST_ES_BASE, 0);																							
			__vmx_vmwrite(GUEST_CS_BASE, 0);																							
			__vmx_vmwrite(GUEST_SS_BASE, 0);																							
			__vmx_vmwrite(GUEST_DS_BASE, 0);																							
			__vmx_vmwrite(GUEST_LDTR_BASE, segment.ldtr.Base);																			
			__vmx_vmwrite(GUEST_TR_BASE, segment.tr.Base);																				
			__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));																		
			__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));																		
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
			__vmx_vmwrite(GUEST_GDTR_BASE, gdtr.gaddress);																				
			__vmx_vmwrite(GUEST_GDTR_LIMIT, gdtr.limit);																				
			__vmx_vmwrite(GUEST_IDTR_BASE, (size_t)idtr.Base);																			
			__vmx_vmwrite(GUEST_IDTR_LIMIT, idtr.Limit);																				
			__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xffffffff);												
			__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));															
			__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));														
			__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_ESP));														
			__vmx_vmwrite(GUEST_IA32_EFER, __readmsr(MSR_EFER));																		
			__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);																					
			__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);																				
			__vmx_vmwrite(VMCS_LINK_POINTER, 0XFFFFFFFFFFFFFFFF);																		
			//buffer64=__vmx_vmwrite(VMX_PREEMPTION_TIMER_VALUE, 0);																				 
		}																																	
		//host-state																															  
		{
			__vmx_vmwrite(HOST_CR0, __readcr0());																			
			__vmx_vmwrite(HOST_CR3, __readcr3());																			
			__vmx_vmwrite(HOST_CR4, __readcr4());																			
			__vmx_vmwrite(HOST_RSP, (SIZE_T)cpuAddress[i].pStack);															
			__vmx_vmwrite(HOST_RIP, (SIZE_T)&VMMEntry);																		
			__vmx_vmwrite(HOST_ES_SELECTOR, KGDT64_R0_DATA);																
			__vmx_vmwrite(HOST_CS_SELECTOR, KGDT64_R0_CODE);																
			__vmx_vmwrite(HOST_SS_SELECTOR, KGDT64_R0_DATA);																
			__vmx_vmwrite(HOST_DS_SELECTOR, KGDT64_R0_DATA);																
			__vmx_vmwrite(HOST_FS_SELECTOR, __Fs() & 0xF8);																	
			__vmx_vmwrite(HOST_GS_SELECTOR, __Gs() & 0xF8);																	
			__vmx_vmwrite(HOST_TR_SELECTOR, __Tr() & 0xF8);																	
			__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));															
			__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));															
			__vmx_vmwrite(HOST_TR_BASE, segment.tr.Base);																	
			__vmx_vmwrite(HOST_GDTR_BASE, gdtr.gaddress);																	
			__vmx_vmwrite(HOST_IDTR_BASE, (size_t)idtr.Base);																
			__vmx_vmwrite(HOST_TR_BASE, segment.tr.Base);																	
			__vmx_vmwrite(HOST_IA32_EFER, __readmsr(MSR_EFER));																
			__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));											
			__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));										
			__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));										
						
		}

	}

	return STATUS_SUCCESS;
}






ULONG32 getBit(ULONG32 bitSetOne,ULONG32 msr)
{
	MsrTure msrture = { 0 };
	ULONG32 ubuffer32=0;
	*(ULONG64*)&msrture = __readmsr(msr);
	ubuffer32 |= msrture.OneoSetOne;
	ubuffer32 &= msrture.ZeroSetZero;
	ubuffer32 |= bitSetOne;
	return ubuffer32;
	
}


void getSegmentInfornation(pSegmentPort pSegment, USHORT Selector)
{

	pSegment->Selector = Selector;
	Gdtr gdtr = { 0 };
	asmsgdt(&gdtr);
	Selector = (Selector >> 3);
	GDTdescriptor gdt;
	gdt = *(PGDTdescriptor)(Selector * 8 + gdtr.gaddress);
	pSegment->AccessRights = ((*(ULONGLONG*)(&gdt)) >> 40) & 0x1F0FF;//11111000011111111
	ULONG64 midaddress, highaddress;
	midaddress = (gdt.Address2 << 16);
	highaddress = (gdt.Adddress3 << 24);
	pSegment->Base = gdt.Address1 | midaddress | highaddress;
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
	if (gdt.S == 0)
	{
		ULONG64 tmp= *(ULONG64*)(Selector * 8 + gdtr.gaddress+8);
		pSegment->Base = (pSegment->Base & 0xffffffff) | (tmp << 32);
	}
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




extern"C" ULONG64 GetGRegister()
{

	ULONG i = KeGetCurrentProcessorNumber();
	gRegister[i].Number = i;
	return (ULONG64)&gRegister[i];
}



