// SampleHook.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "fu.h"
#include "MinHook.h"
#include "include/capstone.h"

#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#pragma comment(lib, "capstone.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#pragma comment(lib, "capstone.x86.lib")
#endif


// 'type cast': from function pointer '...' to data pointer '...'
#pragma warning(disable : 4054)

// nonstandard extension, function / data pointer conversion in expression
#pragma warning(disable : 4152)

typedef int(WINAPI *MESSAGEBOXW)(HWND, LPCWSTR, LPCWSTR, UINT);

// Pointer for calling original MessageBoxW.
MESSAGEBOXW fpMessageBoxW = NULL;

// Detour function which overrides MessageBoxW.
int WINAPI DetourMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption,
                             UINT uType) {
  return fpMessageBoxW(hWnd, L"Hooked!", lpCaption, uType);
}

bool DumpDisassemble(BYTE *bytes, SIZE_T length, ULONG_PTR address,
                     const char *message, const char *label) {
  csh handle = 0;
  if (cs_open(CS_ARCH_X86, (sizeof(void *) == 4) ? CS_MODE_32 : CS_MODE_64,
              &handle) != CS_ERR_OK) {
    return false;
  }

  cs_insn *insn;
  size_t count = cs_disasm(handle, bytes, length, address, 0, &insn);
  if (count > 0) {
    printf("%s %s: ", message, label);
    for (size_t j = 0; j < count; j++) {
      printf("0x%p %s %s\n", (void *)(uintptr_t)insn[j].address,
             insn[j].mnemonic, insn[j].op_str);
    }
    cs_free(insn, count);
  }
  cs_close(&handle);
  return true;
}

int main() {
  // Initialize MinHook.
  if (MH_Initialize() != MH_OK) {
    return 1;
  }

  printf("PID= %d\n", GetCurrentProcessId());

  static const SIZE_T DISAS_BYTES = 6;
  BYTE OriginalBytes[32];
  memcpy(OriginalBytes, &MessageBoxW, sizeof(OriginalBytes));

  // Create a hook for MessageBoxW, in disabled state.
  if (MH_CreateHook(&MessageBoxW, &DetourMessageBoxW,
                    (LPVOID *)&fpMessageBoxW) != MH_OK) {
    return 1;
  }

  DumpDisassemble((BYTE *)&MessageBoxW, DISAS_BYTES, (ULONG_PTR)&MessageBoxW,
                  "[ ]Hook [ ]Concealment", "user32!MessageBoxW");

  // Enable the hook for MessageBoxW.
  if (MH_EnableHook(&MessageBoxW) != MH_OK) {
    return 1;
  }

  // Create concealment but not activate it yet
  if (!FuCreateFakePage(&MessageBoxW, OriginalBytes,
                            sizeof(OriginalBytes))) {
    return 1;
  }

  DumpDisassemble((BYTE *)&MessageBoxW, DISAS_BYTES, (ULONG_PTR)&MessageBoxW,
                  "[X]Hook [ ]Concealment", "user32!MessageBoxW");

  // Avtivate concealment
  if (!FuEnableFakePages()) {
    return 1;
  }

  DumpDisassemble((BYTE *)&MessageBoxW, DISAS_BYTES, (ULONG_PTR)&MessageBoxW,
                  "[X]Hook [X]Concealment", "user32!MessageBoxW");

  // Expected to tell "Hooked!".
  MessageBoxW(NULL, L"Not hooked...", L"MinHook Sample", MB_OK);

  // Deavtivate concealment
  if (!FuDisableFakePages()) {
    return 1;
  }

  DumpDisassemble((BYTE *)&MessageBoxW, DISAS_BYTES, (ULONG_PTR)&MessageBoxW,
                  "[X]Hook [ ]Concealment", "user32!MessageBoxW");

  // Expected to tell "Hooked!".
  MessageBoxW(NULL, L"Not hooked...", L"MinHook Sample", MB_OK);

  // Disable the hook for MessageBoxW.
  if (MH_DisableHook(&MessageBoxW) != MH_OK) {
    return 1;
  }

  DumpDisassemble((BYTE *)&MessageBoxW, DISAS_BYTES, (ULONG_PTR)&MessageBoxW,
                  "[ ]Hook [ ]Concealment", "user32!MessageBoxW");

  // Expected to tell "Not hooked...".
  MessageBoxW(NULL, L"Not hooked...", L"MinHook Sample", MB_OK);

  // Uninitialize MinHook.
  if (MH_Uninitialize() != MH_OK) {
    return 1;
  }

  return 0;
}