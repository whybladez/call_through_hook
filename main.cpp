#include "main.hpp"

using msgbox_t = int(__stdcall*)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
msgbox_t msgbox_o = nullptr;

int __stdcall msgbox_hk(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	printf("HOOK CALLED\n");
	return msgbox_o(hWnd, "hooked", lpCaption, uType);
}

int main()
{
	auto status = MH_Initialize();
	status = MH_CreateHook(reinterpret_cast<void *>(MessageBoxA), &msgbox_hk, reinterpret_cast<void **>(&msgbox_o));
	status = MH_EnableHook(reinterpret_cast<void *>(MessageBoxA));

	MessageBoxA(0, "Hello", "Title", MB_OK);
	auto msgbox_through_hook = call_through_hook::create_call_through_hook<msgbox_t>(reinterpret_cast<uintptr_t>(MessageBoxA), 0x15);
	msgbox_through_hook(0, "Hello call through hook", "Title", MB_OK);

	//msgbox_through_hook = call_through_hook::create_call_through_hook<msgbox_t>(reinterpret_cast<uintptr_t>(MessageBoxA)); // may crash
	//msgbox_through_hook(0, "Hello call through hook", "Title", MB_OK);

	system("pause");
	return 0;
}