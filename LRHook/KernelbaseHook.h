#pragma once
#include <detours.h>

// Kernel32 and API-set imports may use distinct wrappers around the same API.
template<typename T>
static T ResolveKernelBaseFunction(const char* name, T fallback)
{
	HMODULE module = GetModuleHandleW(L"KernelBase.dll");
	FARPROC address = module ? GetProcAddress(module, name) : nullptr;
	return address ? reinterpret_cast<T>(address) : fallback;
}

template<typename T>
static T ResolveAdditionalKernel32Function(const char* name, T implementation)
{
	HMODULE module = GetModuleHandleW(L"Kernel32.dll");
	FARPROC address = module ? GetProcAddress(module, name) : nullptr;
	if (!address) return nullptr;
	PVOID target = DetourCodeFromPointer(reinterpret_cast<PVOID>(address), nullptr);
	PVOID original = DetourCodeFromPointer(reinterpret_cast<PVOID>(implementation), nullptr);
	// Two exports can be different jump stubs for the same implementation.
	return target == original ? nullptr : reinterpret_cast<T>(target);
}

template<typename T>
static void AttachKernelFunction(T& implementation, T& wrapper, T hook)
{
	DetourAttach(&(PVOID&)implementation, hook);
	if (wrapper) DetourAttach(&(PVOID&)wrapper, hook);
}

template<typename T>
static void DetachKernelFunction(T& implementation, T& wrapper, T hook)
{
	if (wrapper) DetourDetach(&(PVOID&)wrapper, hook);
	DetourDetach(&(PVOID&)implementation, hook);
}

typedef BOOL(WINAPI* CreateProcessInternalWFn)(
	HANDLE hUserToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	OPTIONAL PHANDLE hRestrictedUserToken
	);
