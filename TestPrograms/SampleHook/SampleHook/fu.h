// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// @brief Declares interfaces to FU APIs.

#ifndef FU_FU_H_
#define FU_FU_H_

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

// Internal use only.
typedef enum {
  kCreateFakePage = 0x11223300,
  kEnableFakePages,
  kDisableFakePages,
  kDeleteFakePages,
} FuHypercall;

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

/// Creates a fake page in a hypervisor without activating it
/// @param start_address        An address to fake with \a fake_bytes
/// @param fake_bytes           A bytes to show for read operation
/// @param size_of_fake_bytes   A size of \a fake_bytes in bytes
/// @return TRUE when a fake page was created
inline BOOL FuCreateFakePage(void *start_address, const BYTE *fake_bytes,
                             SIZE_T size_of_fake_bytes);

/// Enables and activate all created fake pages
/// @return TRUE when the request was processed by a hypervisor
inline BOOL FuEnableFakePages();

/// Disables and deletes all created fake pages
/// @return TRUE when the request was processed by a hypervisor
inline BOOL FuDisableFakePages();

/// Internal use only
inline BOOL FupEnableFakePagesCallback(void *context);

/// Internal use only
inline BOOL FupDisableFakePagesCallback(void *context);

/// Internal use only
inline BOOL FupVmCall(ULONG_PTR hypercall_number, void *context);

/// Internal use only
inline BOOL FupForEachProcessor(BOOL (*callback)(void *), void *context);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

inline BOOL FuCreateFakePage(void *start_address, const BYTE *original_bytes,
                             SIZE_T original_byte_size) {
  typedef struct {
    ULONG64 start_address;
    ULONG64 original_byte_size;
    UCHAR original_bytes[32];
  } FU_CREATE_SHADOW_PARAMETERS;
  C_ASSERT(sizeof(FU_CREATE_SHADOW_PARAMETERS) == 48);

  if (!start_address || !original_byte_size ||
      original_byte_size >
          sizeof(((FU_CREATE_SHADOW_PARAMETERS *)NULL)->original_bytes)) {
    return FALSE;
  }

  // Modify the start_address to cause copy-on-write in case the page is shared.
  // It lets the address be backed by a physical page that is only used for this
  // process. By doing this, only this process's memory is faked and no other
  // processes are affected.
  DWORD old_protect = 0;
  if (!VirtualProtect(start_address, original_byte_size, PAGE_EXECUTE_READWRITE,
                      &old_protect)) {
    return FALSE;
  }
  memmove(start_address, start_address, original_byte_size);
  FlushInstructionCache(GetCurrentProcess(), start_address, original_byte_size);
  if (!VirtualProtect(start_address, original_byte_size, old_protect,
                      &old_protect)) {
    return FALSE;
  }

  // Lock the address to a physical page. This prevents a page from paged out
  if (!VirtualLock(start_address, original_byte_size)) {
    return FALSE;
  }

  FU_CREATE_SHADOW_PARAMETERS params;
  params.start_address = (ULONG64)start_address;
  params.original_byte_size = original_byte_size;
  memset(params.original_bytes, 0, _countof(params.original_bytes));
  memcpy(params.original_bytes, original_bytes, original_byte_size);

  return FupVmCall(kCreateFakePage, &params);
}

inline BOOL FuEnableFakePages() {
  return FupForEachProcessor(FupEnableFakePagesCallback, NULL);
}

inline BOOL FupEnableFakePagesCallback(void *context) {
  UNREFERENCED_PARAMETER(context);
  return FupVmCall(kEnableFakePages, NULL);
}

inline BOOL FuDisableFakePages() {
  FupForEachProcessor(FupDisableFakePagesCallback, NULL);
  return FupVmCall(kDeleteFakePages, NULL);
}

inline BOOL FupDisableFakePagesCallback(void *context) {
  UNREFERENCED_PARAMETER(context);
  return FupVmCall(kDisableFakePages, NULL);
}

// Internal use only; executes \a callback on each processor
// @param callback   A function to execute
// @param context    An arbitrary parameter for \a callback
// @return TRUE when \a callback was executed on all processors or until it
//         returned FALSE
inline BOOL FupForEachProcessor(BOOL (*callback)(void *), void *context) {
  GROUP_AFFINITY original_group_affinity;
  if (!GetThreadGroupAffinity(GetCurrentThread(), &original_group_affinity)) {
    return FALSE;
  }

  BOOL result = FALSE;
  WORD group_count = GetActiveProcessorGroupCount();
  for (WORD group_number = 0; group_number < group_count; ++group_number) {
    DWORD processor_count = GetActiveProcessorCount(group_number);
    for (DWORD processor_number = 0; processor_number < processor_count;
         ++processor_number) {
      GROUP_AFFINITY group_affinity;
      memset(&group_affinity, 0, sizeof(group_affinity));
      group_affinity.Mask = (KAFFINITY)(1) << processor_number;
      group_affinity.Group = group_number;
      if (!SetThreadGroupAffinity(GetCurrentThread(), &group_affinity, NULL)) {
        goto exit;
      }

      if (!callback(context)) {
        break;
      }
    }
  }
  result = TRUE;

exit:;
  SetThreadGroupAffinity(GetCurrentThread(), &original_group_affinity, NULL);
  return result;
}

// Internal use only; issues VMCALL
// @param callback   A hypercall number
// @param context    An arbitrary parameter
// @return TRUE when a VMCALL instruction was executed without an error
inline BOOL FupVmCall(ULONG_PTR hypercall_number, void *context) {
#pragma section(".asm", read, execute)
#if defined(_AMD64_)
  __declspec(allocate(".asm")) static const BYTE CODE[] = {
      0x0F, 0x01, 0xC1, //    vmcall
      0x74, 0x0E,       //    jz      short errorWithCode
      0x72, 0x04,       //    jb      short errorWithoutCode
      0x48, 0x33, 0xC0, //    xor     rax, rax
      0xC3,             //    retn
                        // errorWithoutCode:
      0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00, //    mov     rax, 2
      0xC3,                                     //    retn
                                                // errorWithCode:
      0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, //    mov     rax, 1
      0xC3,                                     //    retn
  };
#else
  __declspec(allocate(".asm")) static const BYTE CODE[] = {
      0x55,                         //    push    ebp
      0x8B, 0xEC,                   //    mov     ebp, esp
      0x8B, 0x4D, 0x08,             //    mov     ecx, [ebp+hypercall_number]
      0x8B, 0x55, 0x0C,             //    mov     edx, [ebp+context]
      0x0F, 0x01, 0xC1,             //    vmcall
      0x74, 0x11,                   //    jz      short errorWithCode
      0x72, 0x06,                   //    jb      short errorWithoutCode
      0x33, 0xC0,                   //    xor     eax, eax
      0xC9,                         //    leave
      0xC2, 0x08, 0x00,             //    retn    8
                                    // errorWithoutCode:
      0xB8, 0x02, 0x00, 0x00, 0x00, //    mov     eax, 2
      0xC9,                         //    leave
      0xC2, 0x08, 0x00,             //    retn    8
                                    // errorWithCode:
      0xB8, 0x01, 0x00, 0x00, 0x00, //    mov     eax, 1
      0xC9,                         //    leave
      0xC2, 0x08, 0x00,             //    retn    8
  };
#endif

  typedef unsigned char(__stdcall * AsmVmxCallType)(
      _In_ ULONG_PTR hypercall_number, _In_opt_ void *context);

#pragma warning(suppress : 4055)
  AsmVmxCallType AsmVmxCall = (AsmVmxCallType)CODE;

  __try {
    return AsmVmxCall(hypercall_number, context) == 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    SetLastError(GetExceptionCode());
    return FALSE;
  }
}

#ifdef __cplusplus
}
#endif

#endif // FU_FU_H_
