#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <cstring>

bool by_operator(const std::string& s, const char* p) { return s == p; }
bool by_strcmp(const std::string& s, const char* p) { return strcmp(s.c_str(), p) == 0; }
bool by_compare(const std::string& s, const char* p) { return s.compare(p) == 0; }
