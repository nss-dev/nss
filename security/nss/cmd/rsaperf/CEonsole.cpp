// CEonsole.cpp : Defines the entry point for the application.
//

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>

extern "C" int main(int inArgc, char**inArgv, char**inEnv);

int WINAPI WinMain(	HINSTANCE hInstance,
					HINSTANCE hPrevInstance,
					LPTSTR    lpCmdLine,
					int       nCmdShow)
{
    //
    // Set your arguments to main here.
    //
    char* argv[] = {
        "rsaperf.exe", // name of executable.

//      "--help",
	"-d", "/Temp",
	"-n", "none",
	"-s",
	"-i", "100",

        NULL // leave as last one.
    };
    int argc = sizeof(argv) / sizeof(char*) - 1;
    
    //
    // Rewrite stdin, stdout, stderr handles.
    //
    FILE* redir_stdin  = _wfreopen(_T("\\Temp\\stdin.txt"),  _T("r"), stdin);
    FILE* redir_stdout = _wfreopen(_T("\\Temp\\stdout.txt"), _T("w"), stdout);
    FILE* redir_stderr = _wfreopen(_T("\\Temp\\stderr.txt"), _T("w"), stderr);

    //
    // Invoke main.
    //
    int mainRetval = main(argc, argv, NULL);

    return 0;
}
