// Copyright (c) 2015-2018, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements FU functions.

#include "FU_Hypervisor.h"
#include <ntimage.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"

extern "C" {
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

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) static void FupCreateProcessNotifyRoutine(
    _In_ HANDLE parent_pid, _In_ HANDLE pid, _In_ BOOLEAN create);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, FuInitialization)
#pragma alloc_text(PAGE, FuTermination)
#pragma alloc_text(PAGE, FupCreateProcessNotifyRoutine)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

_Use_decl_annotations_ NTSTATUS FuInitialization() {
  PAGED_CODE();

  auto status =
      PsSetCreateProcessNotifyRoutine(FupCreateProcessNotifyRoutine, FALSE);
  return status;
}

_Use_decl_annotations_ void FuTermination() {
  PAGED_CODE();

  PsSetCreateProcessNotifyRoutine(FupCreateProcessNotifyRoutine, TRUE);
}

_Use_decl_annotations_ static void FupCreateProcessNotifyRoutine(
    HANDLE parent_pid, HANDLE pid, BOOLEAN create) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(parent_pid);
  UNREFERENCED_PARAMETER(pid);

  if (create) {
    return;
  }

  UtilForEachProcessor(
      [](void* context) {
        UNREFERENCED_PARAMETER(context);
        return UtilVmCall(HypercallNumber::kApiMonDisableConcealment, nullptr);
      },
      nullptr);

  UtilVmCall(HypercallNumber::kApiMonDeleteConcealment, nullptr);
}

}  // extern "C"
