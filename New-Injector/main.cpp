#include "injector.h"


const char szDllFile[] = "C:\\Development\\Cheating\\My Projects\\Active\\blankdll\\build\\Debug\\blank.dll";
const char szProcName[] = "CalculatorApp.exe";




int main()
{

	std::cout << "Injecting " << szDllFile << " into " << szProcName << std::endl;
	
	PROCESSENTRY32 procEntry32{ 0 };

	procEntry32.dwSize = sizeof(procEntry32);


	HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcSnap == INVALID_HANDLE_VALUE)
	{
		DWORD dwError = GetLastError();
		std::cout << "Failed to create process snapshot. Error code: " << dwError << std::endl;
		system("pause");
		return 1;
	}

	std::cout << "Process snapshot created." << std::endl;


	DWORD dwProcId = 0;
	BOOL bRet = Process32First(hProcSnap, &procEntry32);
	while (bRet) {

		if (!strcmp(procEntry32.szExeFile, szProcName)) {
			dwProcId = procEntry32.th32ProcessID;
			break;
		}
		bRet = Process32Next(hProcSnap, &procEntry32);
		
	}

	CloseHandle(hProcSnap);

	std::cout << "Process ID: " << dwProcId << std::endl;

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS | THREAD_ALL_ACCESS, FALSE, dwProcId);

	if (!hProc)
	{
		DWORD dwError = GetLastError();
		std::cout << "Failed to open process. Error code: " << dwError << std::endl;
		system("pause");
		return 1;
	}

	std::cout << "Process opened." << std::endl;

	if (!ManualMap(hProc, szDllFile))
	{
		CloseHandle(hProc);

		DWORD dwError = GetLastError();
		std::cout << "Failed to inject DLL. Error code: " << dwError << std::endl;
		system("pause");
		return 1;
	}

	std::cout << "DLL injected." << std::endl;


	CloseHandle(hProc);

	std::cout << "Process handle closed." << std::endl;



	return 0;
}