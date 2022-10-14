#include<Windows.h>
#include<string>
#include"Int3Hook.h"


Int3Hook* hook;

void hookCallBack(PCONTEXT debug_context,void *arg)
{
	OutputDebugStringW(L"Hook�ϵ㴥����");
	OutputDebugStringW((wchar_t*)arg);
#ifdef _WIN64
	OutputDebugStringW(std::to_wstring(debug_context->Rax).c_str()); //��ȡrax��ֵ
#else
	OutputDebugStringW(std::to_wstring(debug_context->Eax).c_str()); //��ȡeax��ֵ
#endif
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		const wchar_t* arg = L"������";
#ifdef _WIN64
		hook = new Int3Hook((char*)GetModuleHandleA("ReactorWindowsServer.exe") + 0x6A6E0, 5, hookCallBack��(void*)arg);
#else
		
		hook = new Int3Hook((char*)GetModuleHandleA("WeChatWin.dll") + 0x7A6C91, 2, hookCallBack, (void*)arg);
#endif // WECHAR

		
		if (hook->state() == Int3Hook::ok)
		{
			OutputDebugStringW(L"Hook��װ�ɹ�");
		}
		else
		{
			OutputDebugStringW(L"Hook��װʧ��");
			delete hook;
			hook = nullptr;
		}
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}