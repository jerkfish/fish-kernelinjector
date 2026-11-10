// Test target: a harmless process named left4dead2.exe so the injector's
// Toolhelp32 lookup finds it. It sleeps long enough to outlive the whole
// behavioral suite (the harness starts a fresh instance per binary run).
#include <windows.h>

int main(void)
{
    Sleep(120000);
    return 0;
}
