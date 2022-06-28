#pragma once
#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <map>
#include <Ntsecapi.h>
#include <DbgHelp.h>
#include <Psapi.h>

char input_fuzzer[0x4000];
/*Define STATUS_SUCCESS*/
#ifndef NT_SUCCESS
#define NT_SUCCESS(x) ((x)>=0)
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif







typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT                  Flags;
	USHORT                  Length;
	ULONG                   TimeStamp;
	UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	BOOLEAN                 Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG                   MaximumLength;
	ULONG                   Length;
	ULONG                   Flags;
	ULONG                   DebugFlags;
	PVOID                   ConsoleHandle;
	ULONG                   ConsoleFlags;
	HANDLE                  StdInputHandle;
	HANDLE                  StdOutputHandle;
	HANDLE                  StdErrorHandle;
	UNICODE_STRING          CurrentDirectoryPath;
	HANDLE                  CurrentDirectoryHandle;
	UNICODE_STRING          DllPath;
	UNICODE_STRING          ImagePathName;
	UNICODE_STRING          CommandLine;
	PVOID                   Environment;
	ULONG                   StartingPositionLeft;
	ULONG                   StartingPositionTop;
	ULONG                   Width;
	ULONG                   Height;
	ULONG                   CharWidth;
	ULONG                   CharHeight;
	ULONG                   ConsoleTextAttributes;
	ULONG                   WindowFlags;
	ULONG                   ShowWindowFlags;
	UNICODE_STRING          WindowTitle;
	UNICODE_STRING          DesktopName;
	UNICODE_STRING          ShellInfo;
	UNICODE_STRING          RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_FREE_BLOCK {
	_PEB_FREE_BLOCK* Next;
	ULONG                   Size;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef void(*PPEBLOCKROUTINE)(
	PVOID PebLock
	);

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBaseAddress;
	PPEB_LDR_DATA           Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PPEBLOCKROUTINE         FastPebLockRoutine;
	PPEBLOCKROUTINE         FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PPEB_FREE_BLOCK         FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, * PPEB;



typedef NTSTATUS(NTAPI* myNtMapViewOfSection)
(HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);



typedef struct _SECTION_BASIC_INFORMATION {
	PVOID         Base;
	ULONG         Attributes;
	LARGE_INTEGER Size;
} SECTION_BASIC_INFORMATION, * PSECTION_BASIC_INFORMATION;

// http://undocumented.ntinternals.net/source/usermode/structures/section_image_information.html
typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID                   EntryPoint;
	unsigned long long                   StackZeroBits;
	unsigned long long                   StackReserved;
	ULONGLONG                   StackCommit;
	ULONGLONG                   ImageSubsystem;
	DWORD                    SubSystemVersionLow;
	DWORD                    SubSystemVersionHigh;
	ULONGLONG                   Unknown1;
	ULONGLONG                   ImageCharacteristics;
	ULONGLONG                   ImageMachineType;
	ULONGLONG                   Unknown2[3];
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

typedef enum _SECTION_INFORMATION_CLASS
{
	SectionBasicInformation, // q; SECTION_BASIC_INFORMATION
	SectionImageInformation, // q; SECTION_IMAGE_INFORMATION
	SectionRelocationInformation, // q; PVOID RelocationAddress // name:wow64:whNtQuerySection_SectionRelocationInformation // since WIN7
	SectionOriginalBaseInformation, // PVOID BaseAddress
	SectionInternalImageInformation, // SECTION_INTERNAL_IMAGE_INFORMATION // since REDSTONE2
	MaxSectionInfoClass
} SECTION_INFORMATION_CLASS;

typedef NTSYSAPI NTSTATUS NTAPI myNtQuerySection(
	IN HANDLE               SectionHandle,
	IN SECTION_INFORMATION_CLASS InformationClass,
	OUT PVOID               InformationBuffer,
	IN ULONG                InformationBufferSize,
	OUT PULONG              ResultLength OPTIONAL);






typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;



char tramp2[13] = {
	0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // mov r10, NEW_LOC_@ddress
	0x41, 0xFF, 0xE2                                                    // jmp r10
};
char tramp2_old[13]; /*Thanks Adepts of 0xCC*/


/*Not Used*/







NTSTATUS hooked_ntmap(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);

BOOL hook_ntmap(HANDLE hProc) /*Function to hook NtMapViewOfSection*/
{
	myNtMapViewOfSection NtMap;
	NtMap = (myNtMapViewOfSection)GetProcAddress(GetModuleHandleA("NTDLL.dll"), "NtMapViewOfSection");
	if (!NtMap)
		exit(-1);
	DWORD written3;


	VirtualProtect(NtMap, sizeof NtMap, PAGE_EXECUTE_READWRITE, &written3);


	void* hook_addr = (void*)hooked_ntmap;


	memcpy(tramp2_old, NtMap, sizeof tramp2_old); /*Save the value previous to hooking*/
	memcpy(&tramp2[2], &hook_addr, sizeof hook_addr);

	DWORD old3;

	VirtualProtect(tramp2, sizeof tramp2, PAGE_EXECUTE_READWRITE, &old3);


	if (!WriteProcessMemory(hProc, (LPVOID*)NtMap, &tramp2, sizeof tramp2, NULL))
	{
		return -1;
	}
	return 1;
}



BOOL restore_ntmap(HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect) /*Restore NtMapViewOfSection to previous hooking*/
{
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
	myNtMapViewOfSection NtMap;
	NtMap = (myNtMapViewOfSection)GetProcAddress(GetModuleHandleA("NTDLL.dll"), "NtMapViewOfSection");
	DWORD written2, written3;


	VirtualProtect(NtMap, sizeof NtMap, PAGE_EXECUTE_READWRITE, &written2);
	VirtualProtect(tramp2_old, sizeof tramp2_old, PAGE_EXECUTE_READWRITE, &written3);

	//WriteProcessMemory(hProc, &CreateProcessInternalW, &hook_CreateProcessA, sizeof CreateProcessInternalW, NULL);
	//WriteProcessMemory(hProc, &CreateProcessInternalW2, &hook_CreateProcessA, sizeof CreateProcessInternalW2, NULL);
	if (!WriteProcessMemory(hProc, NtMap, &tramp2_old, sizeof tramp2_old, NULL))
	{
		return FALSE;
	}
	NTSTATUS status = NtMap(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
	if (!NT_SUCCESS(status))
		return 0;
	return 1;

}


BOOL restore_hook_image_notification(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
	restore_ntmap(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
	/*	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
		hook_ntmap(hProc);*/ /*If you want to always have the function hooked after calling the real NtMapViewOfSection (encrypt memory in malware)*/
	return TRUE;

}


int filter(unsigned int code)
{
	if (code == STATUS_ACCESS_VIOLATION)
	{
		return EXCEPTION_EXECUTE_HANDLER;
	}
}

IMAGE_DOS_HEADER* oldHeaders;
IMAGE_NT_HEADERS64* oldNtHeaders;

NTSTATUS hooked_ntmap(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
	oldHeaders = (PIMAGE_DOS_HEADER)malloc(sizeof(IMAGE_DOS_HEADER));
	oldNtHeaders = (PIMAGE_NT_HEADERS64)malloc(sizeof(IMAGE_NT_HEADERS64));
	/*Not used, we tried to modify the PE32 magic bytes in the Section before it's mapped, but after some try/error it seems not possible*/
	myNtQuerySection* NtQuerySection = (myNtQuerySection*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySection"); 
	SECTION_IMAGE_INFORMATION section;
	NTSTATUS status;

	/*status = NtQuerySection(
		SectionHandle,
		SectionImageInformation,
		&section,
		sizeof(SECTION_IMAGE_INFORMATION),
		NULL
	);

	if (!NT_SUCCESS(status))
		printf("Status is: 0x%x\n", status);
	DWORD old, old2;
	ULONGLONG addr_of_module = (ULONGLONG)section.EntryPoint - 0x1870;*/


	__try
	{

		DWORD oldProtection, oldProtection_dos, oldProtection_nt; /*Modify NT / DOS Headers to fuzzer input*/
		LPVOID imageBase = GetModuleHandleA(NULL);
		PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
		PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((unsigned long long)imageBase + dosHeaders->e_lfanew);
		VirtualProtect((void*)dosHeaders, 0x1, PAGE_EXECUTE_READWRITE, &oldProtection_dos);
		VirtualProtect((void*)ntHeaders, 0x1, PAGE_EXECUTE_READWRITE, &oldProtection_dos);
		memcpy(oldHeaders, dosHeaders, sizeof(IMAGE_DOS_HEADER));
		memcpy(oldNtHeaders, ntHeaders, sizeof(IMAGE_NT_HEADERS64));


		memcpy(dosHeaders, input_fuzzer, sizeof(IMAGE_DOS_HEADER));
		memcpy(ntHeaders, input_fuzzer, sizeof(IMAGE_DOS_HEADER));

		/*MEMORY_BASIC_INFORMATION basic;
		for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) //iteramos las secciones
		{
			PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned long long)IMAGE_FIRST_SECTION(ntHeaders) + ((unsigned long long)IMAGE_SIZEOF_SECTION_HEADER * i));
			unsigned long long size_section = hookedSectionHeader->Misc.VirtualSize;
			//Guardamos el addr de la seccion text (coincide con el addr de mi propia seccion text de mi dll, gracias microsoft!!
			unsigned long long hookedAddr = hookedSectionHeader->VirtualAddress;
			LPVOID addr = LPVOID((unsigned long long)imageBase + hookedSectionHeader->VirtualAddress);
			//Comprobamos el tamano de memoria que podemos leer de ahi, para que no de por saco
			VirtualQueryEx(GetCurrentProcess(), addr, &basic, sizeof(MEMORY_BASIC_INFORMATION));
			bool isProtected = VirtualProtect((LPVOID)((unsigned long long)hookedSectionHeader + (unsigned long long)imageBase), basic.RegionSize - 2000, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy(addr, input_fuzzer, basic.RegionSize - 2000);


		}*/


		BOOL restore = restore_hook_image_notification(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
		memcpy(dosHeaders, oldHeaders, sizeof(IMAGE_DOS_HEADER)); /*Restore the old headers after calling real NtMapViewOfSection*/
		memcpy(ntHeaders, oldNtHeaders, sizeof(IMAGE_DOS_HEADER));

	}
	__except (filter(GetExceptionCode()))
	{
		BOOL restore = restore_hook_image_notification(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
		/*In case the modification of headers crashes we call NtMapViewOfSection (To avoid fake fuzzer crashes)*/

	}


	return 1;



}







