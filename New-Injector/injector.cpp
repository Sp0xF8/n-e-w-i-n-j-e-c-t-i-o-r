#include "injector.h"


void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);



bool ManualMap(HANDLE hProc, const char* szDllFile) {

	BYTE *						pSrcData			= nullptr;
	IMAGE_NT_HEADERS *			pOldNtHeader		= nullptr;
	IMAGE_OPTIONAL_HEADER64	*	pOldOptHeader		= nullptr;
	IMAGE_FILE_HEADER *			pOldFileHeader		= nullptr;

	BYTE *						pTargetBase			= nullptr;


	DWORD dwCheck = 0;
	if (!GetFileAttributesA(szDllFile)) {
		std::cout << "File not found." << std::endl;
		return false;
	}

	std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);

	if (File.fail()) {
		std::cout << "Failed to open file." << std::endl;
		File.close();
		return false;
	}

	std::cout << "File opened." << std::endl;

	auto FileSize = File.tellg();
	if (FileSize < 0x1000) {

		std::cout << "File is too small. " << FileSize << std::endl;
		File.close();
		return false;
	}

	std::cout << "File size: " << FileSize << std::endl;

	pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)];

	if (!pSrcData) {
		std::cout << "Failed to allocate memory." << std::endl;
		File.close();
		return false;
	}


	std::cout << "Allocated memory." << std::endl;


	File.seekg(0, std::ios::beg);
	File.read(reinterpret_cast<char*>(pSrcData), FileSize);
	File.close();


	std::cout << "Read file data." << std::endl;
	std::cout << pSrcData << std::endl;

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) {
		std::cout << "Invalid DOS header." << std::endl;
		delete[] pSrcData;
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);

	if (pOldNtHeader->Signature != 0x4550) {
		std::cout << "Invalid NT header." << std::endl;
		delete[] pSrcData;
		return false;
	}

	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
		std::cout << "Invalid architecture." << std::endl;
		delete[] pSrcData;
		return false;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
		std::cout << "Invalid architecture." << std::endl;
		delete[] pSrcData;
		return false;
	}
#endif

	std::cout << "Architecture check passed." << GetLastError() << std::endl;


	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, reinterpret_cast<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!pTargetBase) {

		std::cout << "Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;

		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

		std::cout << "Allocating memory in target process. Error: " << GetLastError() << std::endl;
		

		if (!pTargetBase) {

			
			std::cout << "Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
			delete[] pSrcData;
			return false;
		}
	}

	std::cout << "Allocated memory in target process." << std::endl;

	MANUAL_MAPPING_DATA data{ 0 };

	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

	auto * pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);

	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
				std::cout << "Failed to write section data to target process. Error: " << GetLastError() << std::endl;
				delete[] pSrcData;
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	std::cout << "Wrote section data to target process." << std::endl;

	memcpy(pSrcData, &data, sizeof(data));

	if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr)) {
		std::cout << "Failed to write shellcode to target process. Error: " << GetLastError() << std::endl;
		delete[] pSrcData;
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	delete[] pSrcData;

	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!pShellcode) {
		std::cout << "Failed to allocate memory for shellcode. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}


	SIZE_T bytesWritten = 0;
	if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, &bytesWritten )) {
		std::cout << "Failed to write shellcode to target process. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}


	std::cout << "Wrote shellcode to target process. " << bytesWritten << "Written to: " << pShellcode << std::endl;

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);
	

	std::cout << "error: " << GetLastError() << std::endl;


	if (!hThread) {
		std::cout << "Failed to create remote thread. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}

	std::cout << "Created remote thread." << std::endl;	


	CloseHandle(hThread);

	std::cout << "closed handle." << std::endl;


	HINSTANCE hCheck = NULL;

	while (!hCheck) {
		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;

		Sleep(10);
	}

	std::cout << "DLL loaded." << std::endl;

	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);

	return true;
	
}

#define RELOC_FLAG32(x)		((x >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)

#define RELOC_FLAG64(x)		((x >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
	#define RELOC_FLAG RELOC_FLAG64
#else
	#define RELOC_FLAG RELOC_FLAG32
#endif


void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {

	MessageBoxA(0, "Shellcode called.", "Shellcode", 0);

	if (!pData) {
		return;
	}

	BYTE * pBase = reinterpret_cast<BYTE*>(pData);

	std::cout << "Shellcode called. pBase =" << pBase << std::endl;

	auto * pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;

	auto _DllMain = reinterpret_cast<f_dllEntrypoint>(pBase + pOpt->AddressOfEntryPoint);

	BYTE * LocationDelta = pBase - pOpt->ImageBase;

	std::cout << "LocationDelta: " << LocationDelta << std::endl;

	if (LocationDelta) {
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			return;
		}

		auto * pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		while (pRelocData->VirtualAddress) {
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			
			WORD * pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);


			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
				if (RELOC_FLAG(*pRelativeInfo)) {
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}

			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);

		}
	}



	// Resolve imports 4/4

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto * pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (pImportDescr->Name)
		{
			char *szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);

			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR *pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR *pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
			{
				pThunkRef = pFuncRef;
			}

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else
				{
					auto * pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));

					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
				
			}

			++pImportDescr;
		}
	}

	// Call DllMain

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto * pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

		auto * pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);

		for (; pCallback && *pCallback; ++pCallback)
		{
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}



	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}