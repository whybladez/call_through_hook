#pragma once
#include "minhook/src/HDE/hde64.h"

namespace call_through_hook
{
	static uint32_t tracker{0};

	template <typename T>
	T create_call_through_hook(uintptr_t address, size_t length = 0) // length is offset to the first byte of the function
	{
		uint8_t* allocate_shell_code = reinterpret_cast<uint8_t*>(VirtualAlloc(0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
		bool hook_from_minhook = false;

		while (*reinterpret_cast<uint8_t *>(address) == 0xE9)
			address += *reinterpret_cast<int32_t *>(address + 1) + 5;

		uintptr_t temp_address = address;
		while (*reinterpret_cast<uint16_t *>(temp_address) == 0x25FF) // check for minhook
		{
			temp_address = *reinterpret_cast<uintptr_t *>(temp_address + 6);
			hook_from_minhook = true;
		}

		if (hook_from_minhook && length != 0) 
		{
			address -= length;
			for (size_t i = 0; i < length; i++)
				allocate_shell_code[i] = *reinterpret_cast<uint8_t *>(address + i);
		}

		if (hook_from_minhook && length == 0)
		{
			address = temp_address;

			uintptr_t relative_address = *reinterpret_cast<int32_t *>(address + 1) + address + 5;
			address = relative_address;

			while (*reinterpret_cast<uint8_t *>(address) != 0xFF || *reinterpret_cast<uint8_t *>(address + 1) != 0x15) // search for call original
			{
				address++;
			}

			address = *(uint64_t *)(address + *(int32_t *)(address + 2) + 6); // call qword ptr (original)
		}

		if (!hook_from_minhook)
		{
			address = temp_address;

			hde64s hde_data{};
			hde64_disasm((void *)address, &hde_data);

			if (hde_data.flags & F_ERROR) // decode error
				return nullptr;

			if (!hde_data.len) // 0 length for decode
				return nullptr;

			if ((hde_data.modrm & 0xC7) == 0x05) // rip relative
				return nullptr;

			uint8_t jmp [] = {0xFF, 0x25, 0x00,0x00,0x00,0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
			*reinterpret_cast<uintptr_t *>(&jmp[6]) = address + hde_data.len; // write address to jmp shellcode

			if (tracker + sizeof(jmp) + hde_data.len > 0x1000) // need to increase section size
				return nullptr;

			for (int i = 0; i < hde_data.len; i++)
			{
				allocate_shell_code[tracker + i] = *reinterpret_cast<uint8_t *>(address + i);
			}

			for (int i = 0; i < sizeof(jmp); i++)
			{
				allocate_shell_code[tracker + hde_data.len + i] = jmp[i];
			}
		}

		return reinterpret_cast<T>(&allocate_shell_code[tracker]);
	}
}