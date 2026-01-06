#include "vmx.h"

VMXCPUPCB vmxCpuPcbs[128] = { 0 };

PVMXCPUPCB VmxGetCpuPcb(ULONG cpuNumber)
{
	return &vmxCpuPcbs[cpuNumber];
}

PVMXCPUPCB VmxGetCurrentCpuPcb()
{
	ULONG cpuNumber = KeGetCurrentProcessorNumberEx(NULL);
	return VmxGetCpuPcb(cpuNumber);
}
