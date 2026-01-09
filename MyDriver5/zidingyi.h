#pragma once
#define ERROR_³É¹¦ 0xE0000000
#define ERROR_Ê§°Ü 0xE0000001


#define MiGetPxeAddress(BASE, VA) ((PMMPTE)BASE + ((ULONG32)(((ULONG64)(VA) >> 39) & 0x1FF)))
#define MiGetPpeAddress(BASE, VA) ((PMMPTE)(((((ULONG64)VA & 0xFFFFFFFFFFFF) >> 30) << 3) + BASE))
#define MiGetPdeAddress(BASE, VA) ((PMMPTE)(((((ULONG64)VA & 0xFFFFFFFFFFFF) >> 21) << 3) + BASE))
#define MiGetPteAddress(BASE, VA) ((PMMPTE)(((((ULONG64)VA & 0xFFFFFFFFFFFF) >> 12) << 3) + BASE))