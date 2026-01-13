#pragma once
#define ERROR_成功 0xE0000000
#define ERROR_失败 0xE0000001


#define ERROR_无法打开进程 0xE0000002
#define ERROR_读写地址错误 0xE0000010
#define ERROR_超出读写字节 0xE000000A
#define ERROR_查询内存失败 0xE0000008
#define ERROR_分配内存失败 0xE000000B

#define MiGetPxeAddress(BASE, VA) ((PMMPTE)BASE + ((ULONG32)(((ULONG64)(VA) >> 39) & 0x1FF)))
#define MiGetPpeAddress(BASE, VA) ((PMMPTE)(((((ULONG64)VA & 0xFFFFFFFFFFFF) >> 30) << 3) + BASE))
#define MiGetPdeAddress(BASE, VA) ((PMMPTE)(((((ULONG64)VA & 0xFFFFFFFFFFFF) >> 21) << 3) + BASE))
#define MiGetPteAddress(BASE, VA) ((PMMPTE)(((((ULONG64)VA & 0xFFFFFFFFFFFF) >> 12) << 3) + BASE))