// Test target: a harmless process named left4dead2.exe so the injector's
// Toolhelp32 lookup finds it. It sleeps long enough for the injector to run.
#include <windows.h>

int main(void)
{
    Sleep(30000);
    return 0;
}
