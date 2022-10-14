#include "Int3Hook.h"
std::map<void*, HookInfo*> Int3Hook::_hookInfoList;
std::mutex Int3Hook::_mtx;

Int3Hook::Int3Hook(void* hookaddr, unsigned int hookByteSize, std::function<void(PCONTEXT, void*)> callBack, void* arg)
{
#ifdef _DEBUG
	OutputDebugStringW(L"Int3Hook::Int3Hook()");
#endif // DEBUG
	if (hookaddr == nullptr || callBack == nullptr || hookByteSize <= 0)
	{
		_state = error;
		return;
	}
	_mtx.lock();
	if (Int3Hook::_hookInfoList.find(hookaddr) != Int3Hook::_hookInfoList.end())
	{
		_state = error;
		_mtx.unlock();
		return;
	}
	_mtx.unlock();
	_hookInfo.callBack = callBack;
	_hookInfo.arg = arg;
	_hookInfo.hookaddr = hookaddr;
	_hookInfo.hookByteSize = hookByteSize;
	_hookInfo.backuspCode = new unsigned char[hookByteSize];
	unsigned char code[] = { 0xcc,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };
	//这么写只是为了兼容64 没办法 x64的jmp地址也是4个字节 只能ret去改变rip的值
#ifdef _WIN64
	int addrPos = 25;
	unsigned char asmcode[] = {
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90, //nop
		0x6A,0x00,0x50,0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3E,0x48,0x89,0x44,0x24,0x08,0x58,0xC3     //RET
};
#else
	int addrPos = 21;
	unsigned char asmcode[] = {
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90, //nop
		0x68,0x00,0x00,0x00,0x00,0xC3 //RET
	};
#endif

	
	_hookInfo.asmCodeAddr = VirtualAlloc(nullptr, sizeof(asmcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (_hookInfo.asmCodeAddr == nullptr)
	{
		_state = error;
		return;
	}
	ReadProcessMemory((HANDLE)-1, _hookInfo.hookaddr, _hookInfo.backuspCode, _hookInfo.hookByteSize, 0);
	memcpy(asmcode, _hookInfo.backuspCode, _hookInfo.hookByteSize);

	//改变机器码中要返回的地址
	* (char**)(asmcode + addrPos) = (char*)(((char*)_hookInfo.hookaddr + _hookInfo.hookByteSize));

	WriteProcessMemory((HANDLE)-1, _hookInfo.asmCodeAddr, asmcode, sizeof(asmcode), NULL);
	_mtx.lock();
	if (Int3Hook::_hookInfoList.size() == 0)
	{
		AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)(Int3Hook::ExceptionFilter));
	}
	WriteProcessMemory((HANDLE)-1, _hookInfo.hookaddr, code, _hookInfo.hookByteSize, NULL);
	Int3Hook::_hookInfoList.insert(std::make_pair(_hookInfo.hookaddr, &_hookInfo));
	_mtx.unlock();
	_state = ok;
}

Int3Hook::HookState Int3Hook::state()
{
#ifdef _DEBUG
	OutputDebugStringW(L"Int3Hook::state()");
#endif // DEBUG
	return _state;
}

Int3Hook::~Int3Hook()
{
#ifdef _DEBUG
	OutputDebugStringW(L"Int3Hook::~Int3Hook()");
#endif // DEBUG
	_mtx.lock();
	auto it = Int3Hook::_hookInfoList.find(_hookInfo.hookaddr);
	if (it != Int3Hook::_hookInfoList.end())
	{
		WriteProcessMemory((void*)-1, _hookInfo.hookaddr, _hookInfo.backuspCode, _hookInfo.hookByteSize, NULL);
		Int3Hook::_hookInfoList.erase(it);
	}
	if (_hookInfo.asmCodeAddr != nullptr)
	{
		VirtualFree(_hookInfo.asmCodeAddr, 0, MEM_RELEASE);
		_hookInfo.asmCodeAddr = nullptr;
	}
	if (_hookInfo.backuspCode != nullptr)
	{
		delete[] _hookInfo.backuspCode;
	}
	if (Int3Hook::_hookInfoList.empty())
	{
		RemoveVectoredExceptionHandler(Int3Hook::ExceptionFilter);
	}
	_mtx.unlock();
}

LONG Int3Hook::ExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)
{
#ifdef _DEBUG
	OutputDebugStringW(L"Int3Hook::ExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)");
#endif // DEBUG
	void* ExAddr = ExceptionInfo->ExceptionRecord->ExceptionAddress;
	_mtx.lock();
	auto it = Int3Hook::_hookInfoList.find(ExAddr);
	if (it != Int3Hook::_hookInfoList.end())
	{
		_mtx.unlock();
		it->second->callBack(ExceptionInfo->ContextRecord,it->second->arg);
		
#ifdef _WIN64
		ExceptionInfo->ContextRecord->Rip = (DWORD64)it->second->asmCodeAddr;
#else
		ExceptionInfo->ContextRecord->Eip = (DWORD)it->second->asmCodeAddr;
#endif 

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	_mtx.unlock();
	return EXCEPTION_CONTINUE_SEARCH;
}
