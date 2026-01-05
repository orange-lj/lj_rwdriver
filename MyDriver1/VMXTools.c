#include "VMXTools.h"
#include "VMXDefine.h"
#include <intrin.h>

BOOLEAN VmxIsCheckBIOSSupport()
{
	ULONG64 value = __readmsr(IA32_FEATURE_CONTROL);

	return (value & 0x5) == 0x5;
}

BOOLEAN VmxIsCheckCPUIDSupport()
{
	int cpuidinfo[4];

	__cpuidex(cpuidinfo, 1, 0);

	return (cpuidinfo[2] >> 5) & 1;
}

BOOLEAN VmxIsCheckCR4Support()
{
	ULONG64 mcr4 = __readcr4();

	return (mcr4 >> 13) & 1;
}