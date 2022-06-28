// dllmain.cpp : Define el punto de entrada de la aplicación DLL.
#define _CRT_SECURE_NO_WARNINGS
#include "pch.h"
#define _CRT_SECURE_NO_WARNINGS
#include "definitions.h"
#include <time.h>

#pragma warning(disable:4996)
void modify_nt_headers(const char* input)
{
	return;
}

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION* PPROCESS_BASIC_INFORMATION;



typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);

typedef void(WINAPI* myRtlFreeUnicodeString) (
	PUNICODE_STRING UnicodeString
	);


typedef STRING* PANSI_STRING;
typedef STRING ANSI_STRING;

typedef NTSTATUS(WINAPI* myRtlAnsiStringToUnicodeString) (
	PUNICODE_STRING DestinationString,
	PANSI_STRING   SourceString,
	BOOLEAN         AllocateDestinationString
	);


typedef PCSTR PCSZ;

typedef VOID(WINAPI* myRtlInitAnsiString) (
	PANSI_STRING          DestinationString,
	__drv_aliasesMem PCSZ SourceString
	);

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef VOID(WINAPI* myRtlCopyUnicodeString) (
	PUNICODE_STRING  DestinationString,
	PCUNICODE_STRING SourceString
	);


typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID Reserved3[2];
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
#pragma warning(push)
#pragma warning(disable: 4201) // we'll always use the Microsoft compiler
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	} DUMMYUNIONNAME;
#pragma warning(pop)
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;





PPEB locate_PEB()
{
	HMODULE hLibrary = GetModuleHandleW(L"ntdll.dll");
	FARPROC fpNtQueryInformationProcess = GetProcAddress
	(
		hLibrary,
		"NtQueryInformationProcess"
	);

	if (!fpNtQueryInformationProcess)
		return 0;
	PROCESS_BASIC_INFORMATION BasicInfo;
	DWORD dwSize = NULL;
	_NtQueryInformationProcess ntQueryInformationProcess =
		(_NtQueryInformationProcess)fpNtQueryInformationProcess;
	/*Information del proceso suspendido para sacar la direccion del PEB*/
	NTSTATUS status = (*ntQueryInformationProcess)((HANDLE)0xffffffffffffffff, 0, &BasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &dwSize);
	DWORD64 returnLength;


	return  BasicInfo.PebBaseAddress;

}

int filter(ULONG exception_code)
{
	return EXCEPTION_EXECUTE_HANDLER;
}

typedef struct parameters
{
	UNICODE_STRING CurrentDirectoryPath;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopName;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	UNICODE_STRING DosPath;

} peb_parameters, * ppeb_parameters;

ppeb_parameters myParameters;


int restore_parameters(PEB* pebAddress)
{
	pebAddress->ProcessParameters->CurrentDirectoryPath = myParameters->CurrentDirectoryPath;
	pebAddress->ProcessParameters->DllPath = myParameters->DllPath;
	pebAddress->ProcessParameters->ImagePathName = myParameters->ImagePathName;
	pebAddress->ProcessParameters->CommandLine = myParameters->CommandLine;
	pebAddress->ProcessParameters->WindowTitle = myParameters->WindowTitle;
	pebAddress->ProcessParameters->DesktopName = myParameters->DesktopName;
	pebAddress->ProcessParameters->ShellInfo = myParameters->ShellInfo;
	pebAddress->ProcessParameters->RuntimeData = myParameters->RuntimeData;

	pebAddress->ProcessParameters->DLCurrentDirectory->DosPath = myParameters->DosPath;
	return 1;
}

int modify_parameters(PEB* pebAddress)
{
	myParameters = (ppeb_parameters)malloc(sizeof(peb_parameters));
	myRtlFreeUnicodeString RtlFreeUnicodeString = (myRtlFreeUnicodeString)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlFreeUnicodeString");
	myRtlAnsiStringToUnicodeString RtlAnsiStringToUnicodeString = (myRtlAnsiStringToUnicodeString)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAnsiStringToUnicodeString");
	myRtlInitAnsiString RtlInitAnsiString = (myRtlInitAnsiString)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlInitAnsiString");
	myRtlCopyUnicodeString RtlCopyUnicodeString = (myRtlCopyUnicodeString)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlCopyUnicodeString");
	ANSI_STRING string;
	UNICODE_STRING string_unicode;
	RtlInitAnsiString(&string, input_fuzzer);
	RtlAnsiStringToUnicodeString(&string_unicode, &string, TRUE);

	memcpy(&myParameters->CurrentDirectoryPath, &pebAddress->ProcessParameters->CurrentDirectoryPath, sizeof(UNICODE_STRING));
	memcpy(&myParameters->DllPath, &pebAddress->ProcessParameters->DllPath, sizeof(UNICODE_STRING));
	memcpy(&myParameters->ImagePathName, &pebAddress->ProcessParameters->ImagePathName, sizeof(UNICODE_STRING));
	memcpy(&myParameters->CommandLine, &pebAddress->ProcessParameters->CommandLine, sizeof(UNICODE_STRING));
	memcpy(&myParameters->WindowTitle, &pebAddress->ProcessParameters->WindowTitle, sizeof(UNICODE_STRING));
	memcpy(&myParameters->DesktopName, &pebAddress->ProcessParameters->DesktopName, sizeof(UNICODE_STRING));
	memcpy(&myParameters->ShellInfo, &pebAddress->ProcessParameters->ShellInfo, sizeof(UNICODE_STRING));
	memcpy(&myParameters->RuntimeData, &pebAddress->ProcessParameters->RuntimeData, sizeof(UNICODE_STRING));
	memcpy(&myParameters->DosPath, &pebAddress->ProcessParameters->DLCurrentDirectory->DosPath, sizeof(UNICODE_STRING));


	pebAddress->ProcessParameters->CurrentDirectoryPath = string_unicode;
	pebAddress->ProcessParameters->DllPath = string_unicode;
	pebAddress->ProcessParameters->ImagePathName = string_unicode;
	pebAddress->ProcessParameters->CommandLine = string_unicode;
	pebAddress->ProcessParameters->WindowTitle = string_unicode;
	pebAddress->ProcessParameters->DesktopName = string_unicode;
	pebAddress->ProcessParameters->ShellInfo = string_unicode;
	pebAddress->ProcessParameters->RuntimeData = string_unicode;

	pebAddress->ProcessParameters->DLCurrentDirectory->DosPath = string_unicode;




	if (RtlFreeUnicodeString)
		RtlFreeUnicodeString(&string_unicode);
	return 1;


}

int modify_ldr(PEB* pebAddress)
{
	signed int iSecret; /*To random numbers*/
	_PEB_LDR_DATA* LdrData = pebAddress->Ldr; /*Locate _PEB_LDR_DATA*/
	_LDR_DATA_TABLE_ENTRY* DataTableEntry = (_LDR_DATA_TABLE_ENTRY*)LdrData->InMemoryOrderModuleList.Flink; /*_LDR_DATA_TABLE_ENTRY pointed by _PEB_LDR_DATA->InMemoryOrderModuleList.Flink*/
	long* newDataTableEntry = (long*)((_LDR_DATA_TABLE_ENTRY*)DataTableEntry->Reserved1); /*Next DataTableEntry pointed by _LDR_DATA_TABLE_ENTRY->Reserved1 (equal to Flink)*/
	_LDR_DATA_TABLE_ENTRY* data = (_LDR_DATA_TABLE_ENTRY*)newDataTableEntry;
	DWORD old;
	VirtualProtect((void*)newDataTableEntry, 0x1, PAGE_READWRITE, &old);
	srand(time(NULL));
	iSecret = rand() % 0x4000 + (-0x2000);
	myRtlFreeUnicodeString RtlFreeUnicodeString = (myRtlFreeUnicodeString)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlFreeUnicodeString");
	myRtlAnsiStringToUnicodeString RtlAnsiStringToUnicodeString = (myRtlAnsiStringToUnicodeString)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAnsiStringToUnicodeString");
	myRtlInitAnsiString RtlInitAnsiString = (myRtlInitAnsiString)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlInitAnsiString");
	myRtlCopyUnicodeString RtlCopyUnicodeString = (myRtlCopyUnicodeString)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlCopyUnicodeString");
	ANSI_STRING string;
	UNICODE_STRING string_unicode;
	RtlInitAnsiString(&string, input_fuzzer);
	RtlAnsiStringToUnicodeString(&string_unicode, &string, TRUE);
	data->FullDllName = string_unicode;
	//	RtlCopyUnicodeString(&data->FullDllName, &string_unicode);

		/*if (RtlFreeUnicodeString)
			RtlFreeUnicodeString(&data->FullDllName);*/
	__try
	{

		data->FullDllName.Length = iSecret;
		data->FullDllName.MaximumLength = iSecret;

	}
	__except (filter(GetExceptionCode()))
	{
		data->FullDllName.Length = iSecret;
		data->FullDllName.MaximumLength = iSecret;
	}

	return 1;

}
extern "C" __declspec(dllexport)  __declspec(noinline) int fuzz(char* data);
int fuzz(char* data)
{

	FILE* fp = fopen(data, "rb");
	if (!fp)
	{
		printf("error\n");
		return 0;
	}
	else
		fread(input_fuzzer, 0x4000, 1, fp);
	printf("Data: %s\n", input_fuzzer);
	fclose(fp);
	printf("Go\n");

	PPEB myPEB = locate_PEB();
	modify_ldr(myPEB);
	modify_parameters(myPEB);
	//hook_ntcreatesection((HANDLE)0xffffffffffffffff);

	hook_ntmap((HANDLE)0xffffffffffffffff);

	HMODULE lib = LoadLibraryA("C:\\Windows\\System32\\calc.exe");
	FreeLibrary(lib);
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, NULL, 796);
	if (!process)
	{
		printf("error\n");
	}
	restore_parameters(myPEB);
	printf("exiting\n");
	return 0;
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

