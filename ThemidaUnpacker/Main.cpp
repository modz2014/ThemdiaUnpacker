#include <windows.h>
#include <iostream>
#include <string>
#include <shlwapi.h>
#include "Dump.h"

// Function to suspend or resume threads of a specified process.
bool ModifyThreadsByProcessID(DWORD processId, bool suspend) {
    // Determine the desired access rights for the threads.
    DWORD desiredAccess = suspend ? THREAD_SUSPEND_RESUME : THREAD_RESUME;

    // Create a snapshot of all running threads.
    HANDLE threadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (threadSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(threadSnapshot, &threadEntry)) {
        CloseHandle(threadSnapshot);
        return false;
    }

    do {
        // Check if the thread belongs to the specified process.
        if (threadEntry.th32OwnerProcessID == processId) {
            // Open the thread and perform the desired action.
            HANDLE threadHandle = OpenThread(desiredAccess, FALSE, threadEntry.th32ThreadID);
            if (threadHandle != NULL) {
                if (suspend) {
                    SuspendThread(threadHandle);
                }
                else {
                    while (ResumeThread(threadHandle) > 0) {}
                }
                CloseHandle(threadHandle);
            }
        }
    } while (Thread32Next(threadSnapshot, &threadEntry));

    CloseHandle(threadSnapshot);
    return true;
}

// Function to check if a specific module (clrjit.dll) is loaded in a process.
bool IsClrjitDLLLoaded(DWORD processId) {
    // Create a snapshot of all loaded modules in the target process.
    HANDLE moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
    if (moduleSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);
    if (Module32First(moduleSnapshot, &moduleEntry)) {
        do {
            // Check if the module name matches "clrjit.dll." 
            if (_tcsicmp(moduleEntry.szModule, _T("clrjit.dll")) == 0) {
                CloseHandle(moduleSnapshot);
                return true;
            }
        } while (Module32Next(moduleSnapshot, &moduleEntry));
    }

    CloseHandle(moduleSnapshot);
    return false;
}

int main(int argc, char* argv[]) {
    // Display a message box with program information.
    MessageBox(nullptr, _T("Themida Unpacker"), _T("Info"), MB_OK);

    if (argc < 2) {
        // Display an error message if the program is not provided with the correct arguments.
        MessageBox(nullptr, _T("Usage: Drag and drop the target file onto the executable."), _T("Error"), MB_OK);
        return 1;
    }

    // Define whether to suspend threads.
    bool suspendThreads = true;

    // The first command-line argument (argv[1]) contains the path to the target file.
    wchar_t targetPath[MAX_PATH];
    _stprintf_s(targetPath, _T("%S"), argv[1]);

    wchar_t pdPath[MAX_PATH] = _T("");

    // Open a file dialog to select the PD file (pd.exe).
    OPENFILENAME ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = _T("PD File (pd.exe)\0pd.exe\0");
    ofn.lpstrFile = pdPath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = _T("Select pd.exe");
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (GetOpenFileName(&ofn) == 0) {
        // Display an error message if the PD file is not selected.
        MessageBox(nullptr, _T("Please select the PD file."), _T("Error"), MB_OK);
        return 1;
    }

    int processId;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    if (CreateProcess(targetPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        // Retrieve the process ID of the newly created process.
        processId = pi.dwProcessId;
        std::wcout << L"WAIT..." << std::endl;

        while (true) {
            if (IsClrjitDLLLoaded(processId)) {
                // If clrjit.dll is loaded, suspend or resume threads as needed.
                ModifyThreadsByProcessID(processId, suspendThreads);
                std::wcout << L"Found clrjit.dll -> LOADED .NET" << std::endl;
               
                    if (Dump(targetPath, pdPath, suspendThreads, processId)) 
                    {

                    // Terminate the process if the dump is successful.
                    TerminateProcess(pi.hProcess, 0);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    return 0;
                }
            }
        }
    }
    else {
        // Display an error message if CreateProcess fails.
        MessageBox(nullptr, _T("Unknown Error: Run as Administrator and 32-bit for _32, 64-bit for _64"), _T("Error"), MB_OK);
        return 1;
    }
}
