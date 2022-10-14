#pragma once
#include<Windows.h>
#include<functional>
#include<map>
#include<mutex>

class HookInfo
{
public:
	inline HookInfo()
		:hookaddr(nullptr), asmCodeAddr(nullptr), callBack(nullptr), hookByteSize(0), backuspCode(nullptr),arg(nullptr)
	{}
	void* hookaddr;
	void* asmCodeAddr;
	std::function<void(PCONTEXT debugContext,void *arg)> callBack;
	void* arg;
	unsigned int hookByteSize;
	unsigned char* backuspCode;
};

class Int3Hook
{
public:
	enum HookState
	{
		ok,
		error,
	};
	/*
	* hookaddr hook地址  不能hook ：jmp的地址  call地址 以及其他跳转地址
	* hookByteSize hook地址的地址的指令占多少个字节 就填多少
	* callBack 回调函数地址
	* arg 参数
	*/
	Int3Hook(void *hookaddr, unsigned int hookByteSize, std::function<void(PCONTEXT, void*)> callBack,void *arg);
	HookState state();
	Int3Hook(const Int3Hook& hook) = delete;
	Int3Hook& operator=(const Int3Hook& hook) = delete;
	~Int3Hook();
private:
	static LONG NTAPI ExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo);
	static std::map<void*, HookInfo*> _hookInfoList;
	static std::mutex _mtx;
	HookInfo _hookInfo;
	HookState _state;
};

