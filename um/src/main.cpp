#include <Windows.h>
#include <cstdio>
#include "driver.h"
#include "injector.h"

int main()
{
    if (!driver().open())
    {
        printf("failed to open driver (error %lu) — is the driver loaded?\n", GetLastError());
        system("pause");
        return 1;
    }
    printf("driver opened\n\n");

    // window class name for the target, DLL to inject
    face_injecor_v2("UnrealWindow", L"Z:/FMM/Farlight/Dumper-7/x64/Release/Dumper-7.dll");
   
    printf("\n");
    system("pause");
    return 0;
}
