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
        "strsclnt.exe", 	// name of executable.
	"-C", "ABCDEFabcdefghijklmnopqrstuvwxy",
//	"-C", "c",		// only RSA_CR4_MD5  CipherSuite
//	"-C", "d",		// only RSA_3DES_SHA CipherSuite
//	"-C", "v",		// only RSA_AES_128_SHA CipherSuite
//	"-C", "y",		// only RSA_AES_256_SHA CipherSuite
	"-c", "2",		// 2 connections
	"-d", "/Temp",		// DB directory
	"-n", "ExtendedSSLUser",// cert nickname
	"-o",			// override cert validity check
//	"-p", "1234",		// port
	"-t", "1",		// 1 thread
	"-v",			// verbose
	"-w", "nss", 		// DB password
//	"www.microsoft.com",	// host
	"windmere.mcom.com",	// host
        NULL 		// leave as last one.
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
    int mainRetVal = main(argc, argv, NULL);
    fprintf(stderr, "main() returned %d\n", mainRetVal);

    return 0;
}
