#pragma once

#include <windows.h>
#include <tchar.h>
#include <shlwapi.h>
#include <string.h>
#include <tlhelp32.h>





// Function declaration for handling the process execution and dumping
bool Dump(const wchar_t* targetPath, const wchar_t* pdPath, bool suspendThreads, DWORD processId)
{
    if (true)
    {
        wchar_t cmdLine[MAX_PATH];
        _stprintf_s(cmdLine, _T("\"%s\" -pid %d"), pdPath, processId);

        wchar_t dumpDir[MAX_PATH] = _T("DUMP");

        if (!PathFileExists(dumpDir)) {
            // If the directory doesn't exist, create it
            if (!CreateDirectory(dumpDir, NULL)) {
                // If CreateDirectory fails, show an error message and return
                MessageBox(nullptr, _T("Failed to create dump directory."), _T("Error"), MB_OK);
                return false;
            }
        }

        PROCESS_INFORMATION pi;
        STARTUPINFO si;
        ZeroMemory(&si, sizeof(si));
        if (CreateProcess(pdPath, cmdLine, NULL, NULL, FALSE, 0, NULL, dumpDir, &si, &pi)) {
            MessageBox(nullptr, _T("DUMPED! If an error occurs, please dump it manually"), _T("Info"), MB_OK);
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return true;
        }
    }
}
