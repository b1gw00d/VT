#include<ntddk.h>
class CPUaddress
{
public:
	PVOID pVMXON;
	PVOID pVMXCS;
	PVOID pStack;
	PHYSICAL_ADDRESS phVMXON;
	PHYSICAL_ADDRESS phVMXCS;
	PHYSICAL_ADDRESS phStack;
};




#pragma pack(1)
typedef struct 
{
	int uknow : 5;
	unsigned int VMX : 1;
	ULONGLONG uknow1 : 58;
}CPUIDrcx;



typedef struct 
{
	unsigned RevId : 32;
	unsigned szVmxOnRegion : 12;
	unsigned ClearBit : 1;
	unsigned Reserved : 3;
	unsigned PhysicalWidth : 1;
	unsigned DualMonitor : 1;
	unsigned MemoryType : 4;
	unsigned VmExitInformation : 1;
	unsigned useTrue : 1;
	unsigned Reserved2 : 8;
} VMX_BASIC_MSR, *PVMX_BASIC_MSR;


typedef struct 
{
	unsigned int PE : 1;
	unsigned int MP : 1;
	unsigned int EM : 1;
	unsigned int TS : 1;
	unsigned int ET : 1;
	unsigned int NE : 1;
	unsigned int : 10;
	unsigned int WP : 1;
	unsigned int : 1;
	unsigned int AM : 1;
	unsigned int : 10;
	unsigned int NW : 1;
	unsigned int CD : 1;
	unsigned int PG : 1;
	unsigned int : 32;
}CR0, *PCR0;


typedef struct 
{
	unsigned int VME : 1;
	unsigned int PVI : 1;
	unsigned int TSD : 1;
	unsigned int DE : 1;
	unsigned int PSE : 1;
	unsigned int PAE : 1;
	unsigned int MCE : 1;
	unsigned int PGE : 1;
	unsigned int PCE : 1;
	unsigned int : 2;
	unsigned int UMIP : 1;
	unsigned int : 1;
	unsigned int VMXE : 1;
	unsigned int SMXE : 1;
	unsigned int : 5;
	unsigned int SMEP : 1;
	unsigned int SMAP : 1;
	unsigned int PKE : 1;
	unsigned int : 9;
	unsigned int : 32;
}CR4, *PCR4;


typedef struct
{
	unsigned int CRn : 4;
	unsigned int AccessType : 2;
	unsigned int LMSWoperand : 1;
	unsigned int Reserve1 : 1;
	unsigned int GPR : 4;
	unsigned int Reserve2 : 4;
	unsigned int LMSWsouce : 16;
	unsigned int Reserve3 : 32;
}ExitQualificationCRn, *pExitQualificationCRn;


typedef struct 
{
	ULONG OneoSetOne;
	ULONG ZeroSetZero;

}MsrTure, *pMsrTure;



typedef struct 
{
	USHORT SegmentLimit;
	USHORT Address1;
	USHORT Address2 : 8;
	USHORT Type : 4;
	USHORT S : 1;
	USHORT DPL : 2;
	USHORT P : 1;
	USHORT SegLimit : 4;
	USHORT AVL : 1;
	USHORT L : 1;
	USHORT DB : 1;
	USHORT G : 1;
	USHORT Adddress3 : 8;
}GDTdescriptor, *PGDTdescriptor;

typedef struct 
{
	USHORT Selector;
	ULONG32 Limit;
	USHORT AccessRights;
	ULONGLONG Base;
}SegmentPort, *pSegmentPort;

typedef struct 
{
	SegmentPort es;
	SegmentPort cs;
	SegmentPort ss;
	SegmentPort ds;
	SegmentPort fs;
	SegmentPort gs;
	SegmentPort ldtr;
	SegmentPort tr;



}Segment, *PSegment;

typedef struct 
{
	unsigned short limit;
	ULONGLONG  gaddress;

}Gdtr, *pGdtr;


typedef struct  
{
	USHORT Limit;
	PVOID Base;
}IDTR;