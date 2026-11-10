// SKernelInjector - recovered source
//
// Reconstructed from SKernelInjector.exe (Win32 Release, MSVC 14.30, 2022-04-20).
// Behaviour preserved exactly, including quirks noted inline. See NOTES/evidence.md.
//
// INFERRED: all user-defined identifiers (CProcess, hProcess, szName, GetProcessId)
// are descriptive reconstructions - the original PDB is not available. The layout and
// calling convention are proven by the binary (sizeof == 0x1C; __thiscall member).

#include <windows.h>
#include <tlhelp32.h>
#include <conio.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <memory>

struct CProcess
{
    HANDLE hProcess;        // +0x00
    std::string szName;     // +0x04 (MSVC x86 std::string is 24 bytes)

    DWORD GetProcessId();
};

DWORD CProcess::GetProcessId()
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(pe);

    if (!Process32First(hSnapshot, &pe))
        return 0;

    do
    {
        // NOTE: strcmp() is used deliberately; /Oi expands it to an inline loop and the
        // binary contains no strcmp import. std::string == const char* produces different
        // code (strlen + length check + memcmp), so that form is ruled out.
        if (strcmp(szName.c_str(), pe.szExeFile) == 0)
        {
            CloseHandle(hSnapshot);
            return pe.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe));

    // QUIRK: snapshot handle is leaked when the process is not found, matching the original.
    return 0;
}

int main()
{
    auto pProcess = std::make_unique<CProcess>();
    pProcess->szName = "left4dead2.exe";

    DWORD dwProcessId = pProcess->GetProcessId();
    if (!dwProcessId)
    {
        printf("Failed getting %s process ID, Make sure your game called left4dead2.exe\n",
               pProcess->szName.c_str());
        printf("Failed process initialization.\n");
    }
    else
    {
        pProcess->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

        // QUIRK: OpenProcess returns NULL on failure, so comparing against
        // INVALID_HANDLE_VALUE never triggers. Preserved from the original.
        if (pProcess->hProcess == INVALID_HANDLE_VALUE)
            printf("Failed process initialization.\n");
    }

    char szDllPath[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, szDllPath);
    strcat_s(szDllPath, "\\VR.dll");
    printf("DLL Path: ");
    printf(szDllPath);          // QUIRK: path used as format string (original behaviour)

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryA =
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");

    LPVOID pRemoteMem = NULL;
    HANDLE hThread = NULL;

    if (pLoadLibraryA &&
        (pRemoteMem = VirtualAllocEx(pProcess->hProcess, NULL, strlen(szDllPath) + 1,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != NULL &&
        WriteProcessMemory(pProcess->hProcess, pRemoteMem, szDllPath,
                           strlen(szDllPath) + 1, NULL) &&
        (hThread = CreateRemoteThread(pProcess->hProcess, NULL, 0, pLoadLibraryA,
                                      pRemoteMem, 0, NULL)) != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(hThread, INFINITE);
        VirtualFreeEx(pProcess->hProcess, pRemoteMem, 0, MEM_RELEASE);
        printf("\nSuccessfully injected, Please close this window!\n\n\n\n");
    }
    else
    {
        printf("\nInjection failed!\n\n\n\n");
    }

    printf("If you experience unexpected errors, Follow the steps below:\n");
    printf("1. Dont run left4dead2.exe in compatibility mode.\n");
    printf("2. Uninstall Reshade/ENB or any d3d9 dll based mods.\n");
    printf("3. Disable all workshop addons.\n");
    printf("4. Disable anti virus softwares.\n\n");

    int nKey = _getwch();
    return nKey;                // original returns the key code from _getwch()
}
