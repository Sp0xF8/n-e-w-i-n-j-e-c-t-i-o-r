#pragma once


#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>


using f_LoadLibA = HINSTANCE(WINAPI*)(const char* lpLibFilename);

using f_GetProcAddress = UINT_PTR(WINAPI*)(HINSTANCE hModule, const char* lpProcName);

using f_dllEntrypoint = BOOL(WINAPI*)(void* hinstDLL, DWORD fdwReason, void* lpvReserved);

struct MANUAL_MAPPING_DATA
{
	f_LoadLibA		pLoadLibraryA;
	f_GetProcAddress	pGetProcAddress;
	HINSTANCE		hMod;
};

bool ManualMap(HANDLE hProc, const char* szDllFile);