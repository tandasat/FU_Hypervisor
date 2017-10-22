// ReadProcMem.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "include/capstone.h"
#pragma comment(lib, "capstone.lib")

bool DumpDisassemble(BYTE *bytes, SIZE_T length, ULONG_PTR address, const char* message, const char* label)
{
  csh handle = 0;
  if (cs_open(CS_ARCH_X86, (sizeof(void *) == 4) ? CS_MODE_32 : CS_MODE_64,
    &handle) != CS_ERR_OK)
  {
    return false;
  }

  cs_insn *insn;
  size_t count = cs_disasm(handle, bytes, length,
    address, 0, &insn);
  if (count > 0)
  {
    printf("%s %s: ", message, label);
    for (size_t j = 0; j < count; j++)
    {
      printf("0x%p %s %s\n", (void *)(uintptr_t)insn[j].address,
        insn[j].mnemonic, insn[j].op_str);
    }
    cs_free(insn, count);
  }
  cs_close(&handle);
  return true;
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    printf(">this.exe pid remote_address\n");
    return 0;
  }

  auto pid = std::stoul(argv[1]);
  auto addr = reinterpret_cast<void *>(std::stoull(argv[2], 0, 16));
  auto handle = OpenProcess(PROCESS_VM_READ, FALSE, pid);
  if (!handle) {
    return 1;
  }

  SIZE_T read = 0;
  UCHAR bytes[32] = {};
  if (!ReadProcessMemory(handle, addr, bytes, sizeof(bytes), &read)) {
    return 1;
  }

  DumpDisassemble(bytes, 6, reinterpret_cast<ULONG_PTR>(addr), "PID", argv[1]);
  return 0;
}
