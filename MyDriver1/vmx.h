#pragma once
#include <ntifs.h>

typedef struct _VMXCPUPCB 
{
	ULONG cpuNumber;
	PVOID VmxOnAddr;
	PHYSICAL_ADDRESS VmxOnPhyAddr;
}VMXCPUPCB,*PVMXCPUPCB;

PVMXCPUPCB VmxGetCpuPcb(ULONG cpuNumber);

PVMXCPUPCB VmxGetCurrentCpuPcb();


int VmxInit();

int VmxInitVmOn();