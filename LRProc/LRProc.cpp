#include<iostream>
#include<Windows.h>
#include<detours.h>
#include<cstdio>
#include<cstring>
#include<vcclr.h>
#include<shellapi.h>
#include<string>
#include<vector>

#include"../LRCommonLibrary/LRCommonLibrary.h"
#pragma comment(lib, "LRCommonLibrary.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

using namespace System::Reflection;
using namespace System::Runtime::InteropServices;

#ifdef _DEBUG
#using <../LRSubMenu/bin/Debug/LRSubMenus.dll>
#else
#using <../LRSubMenu/bin/Release/LRSubMenus.dll>
#endif

static int ShowLaunchError(LPCWSTR action, DWORD error)
{
	if (error == ERROR_SUCCESS)
		error = ERROR_GEN_FAILURE;

	LPWSTR description = nullptr;
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error, 0,
		reinterpret_cast<LPWSTR>(&description), 0, nullptr);

	std::wstring message = std::wstring(action) + L"\n\nError " + std::to_wstring(error);
	if (description)
	{
		message += L": ";
		message += description;
		LocalFree(description);
	}
	MessageBoxW(nullptr, message.c_str(), L"Locale Remulator", MB_OK | MB_ICONERROR);
	return static_cast<int>(error);
}

static DWORD GetProcessElevation(bool& elevated)
{
	elevated = false;
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
		return GetLastError();

	TOKEN_ELEVATION elevation = {};
	DWORD size = 0;
	DWORD error = GetTokenInformation(token, TokenElevation, &elevation,
		sizeof(elevation), &size) ? ERROR_SUCCESS : GetLastError();
	CloseHandle(token);
	elevated = elevation.TokenIsElevated != 0;
	return error;
}

static int RunElevated(LPCWSTR arguments, int showCommand)
{
	std::vector<wchar_t> executable(32768);
	DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
	if (length == 0)
		return ShowLaunchError(L"Could not locate LRProc.exe.", GetLastError());
	if (length >= executable.size())
		return ShowLaunchError(L"The LRProc.exe path is too long.", ERROR_INSUFFICIENT_BUFFER);

	DWORD directorySize = GetCurrentDirectoryW(0, nullptr);
	if (directorySize == 0)
		return ShowLaunchError(L"Could not read the working directory.", GetLastError());
	std::vector<wchar_t> directory(directorySize);
	length = GetCurrentDirectoryW(directorySize, directory.data());
	if (length == 0)
		return ShowLaunchError(L"Could not read the working directory.", GetLastError());
	if (length >= directorySize)
		return ShowLaunchError(L"The working directory changed during startup.", ERROR_INSUFFICIENT_BUFFER);

	HRESULT comResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	if (FAILED(comResult) && comResult != RPC_E_CHANGED_MODE)
		return ShowLaunchError(L"Could not initialize elevation.", static_cast<DWORD>(comResult));

	SHELLEXECUTEINFOW info = {};
	info.cbSize = sizeof(info);
	info.fMask = SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
	info.lpVerb = L"runas";
	info.lpFile = executable.data();
	// Preserve the original quoting, including launcher URLs and empty arguments.
	info.lpParameters = arguments;
	info.lpDirectory = directory.data();
	info.nShow = showCommand;
	BOOL started = ShellExecuteExW(&info);
	DWORD error = started ? ERROR_SUCCESS : GetLastError();
	if (SUCCEEDED(comResult))
		CoUninitialize();
	if (!started)
		return ShowLaunchError(L"Could not start Locale Remulator with administrator privileges.", error);
	return 0;
}

static LPWSTR GetTargetCommandLine(LPWSTR arguments)
{
	while (*arguments == L' ' || *arguments == L'\t')
		++arguments;

	// The first argument is the profile GUID. It may itself be quoted.
	bool quoted = false;
	while (*arguments)
	{
		if (*arguments == L'"')
			quoted = !quoted;
		else if (!quoted && (*arguments == L' ' || *arguments == L'\t'))
			break;
		++arguments;
	}
	while (*arguments == L' ' || *arguments == L'\t')
		++arguments;
	return arguments;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR lpCmdLine, int nCmdShow)
{
	LRCSharpLibrary::LRConfig::CheckConfigFile();

	if (__argc < 3)
	{
		MessageBox(
			NULL,
			TEXT(R"(
Welcome to Locale Remulator x64 command line tool.

Usage: LRProc.exe GUID Path Args

GUID	Guid of the target profile (in LRConfig.xml).
Path	Full path of the target application.
Args	Additional arguments will be passed to the application.

You can also run LREditor to use this applicaction.
				)"
			),
			TEXT("Locale Remulator x64"),
			NULL
		);
		return 0;
	}

	System::String^ Guid = gcnew System::String(__wargv[1]);
	LRCSharpLibrary::LRProfile^ alpha = LRCSharpLibrary::LRConfig::GetProfile(Guid);
	if (alpha->RunAsAdmin)
	{
		bool elevated = false;
		DWORD error = GetProcessElevation(elevated);
		if (error != ERROR_SUCCESS)
			return ShowLaunchError(L"Could not check administrator privileges.", error);
		if (!elevated)
			return RunElevated(lpCmdLine, nCmdShow);
	}

	System::String^ CurrentPath = LRCSharpLibrary::LRConfig::CurrentPath;
	System::String^ DllPath = System::IO::Path::Combine(CurrentPath, "LRHookx64.dll");

	LPSTR dllpath = (LPSTR)(void*)Marshal::StringToHGlobalAnsi(DllPath);

	LPWSTR CommandLine = GetTargetCommandLine(lpCmdLine);

	LRProfile beta;
	beta.CodePage = alpha->CodePage;
	beta.LCID = alpha->LCID;
	beta.Bias = alpha->Bias; // Bias will become negative in HookGetTimeZoneInformation
	beta.HookIME = alpha->HookIME;
	beta.HookLCID = alpha->HookLCID;

	LRConfigFileMap filemap;
	filemap.WrtieConfigFileMap(&beta);

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);
	//std::cout << beta.CodePage;

	BOOL started = DetourCreateProcessWithDllExW(NULL, CommandLine, NULL,
		NULL, FALSE, CREATE_DEFAULT_ERROR_MODE, NULL, NULL,
		&si, &pi, dllpath, NULL);
	DWORD error = started ? ERROR_SUCCESS : GetLastError();
	Marshal::FreeHGlobal(System::IntPtr(dllpath));
	if (!started)
		return ShowLaunchError(L"Could not start the target application.", error);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return 0;
}
