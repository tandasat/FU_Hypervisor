#pragma once
// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements fake page functions.

#include "fake_page.h"
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#include "../HyperPlatform/HyperPlatform/kernel_stl.h"
#include <vector>
#include <memory>
#include <algorithm>
#include <array>

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

// Copy of a page seen by a guest as a result of memory shadowing
struct Page {
  UCHAR* address;  // A page aligned copy of a page
  Page();
  ~Page();
};

// Allocates a non-paged, page-alined page. Issues bug check on failure
Page::Page()
    : address(reinterpret_cast<UCHAR*>(ExAllocatePoolWithTag(
          NonPagedPool, PAGE_SIZE, kHyperPlatformCommonPoolTag))) {
  if (!address) {
    HYPERPLATFORM_COMMON_BUG_CHECK(
        HyperPlatformBugCheck::kCritialPoolAllocationFailure, 0, 0, 0);
  }
}

// De-allocates the allocated page
Page::~Page() { ExFreePoolWithTag(address, kHyperPlatformCommonPoolTag); }

// Contains single fake page data
struct FakePageData {
  void* patch_address;   // An address to be faked
  ULONG_PTR target_cr3;  // CR3 of the target process

  // A copy of a pages where patch_address belongs to. shadow_page_base_for_rw
  // is exposed to a guest for read and write operation against the page of
  // patch_address, and shadow_page_base_for_exec is exposed for execution.
  std::shared_ptr<Page> shadow_page_base_for_exec;

  // Phyisical address of the above two copied pages
  ULONG64 pa_base_for_rw;
  ULONG64 pa_base_for_exec;

  std::array<UCHAR, 32> original_bytes;  // Bytes to show for read operations
};

// Data structure shared across all processors
struct SharedFakePageData {
  std::vector<std::unique_ptr<FakePageData>> all_fp_data;
};

// Data structure for each processor
struct ProcessorFakePageData {
  const FakePageData* last_fp_data;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) static std::unique_ptr<
    FakePageData> FppCreateFakePageData(_In_ SharedFakePageData* shared_fp_data,
                                        _In_ void* context);

static FakePageData* FppFindFakePageDataByPage(
    _In_ const SharedFakePageData* shared_fp_data, _In_ void* address);

static void FppEnableFakePageForExec(_In_ const FakePageData& fp_data,
                                     _In_ EptData* ept_data);

static void FppEnableFakePageForRw(_In_ const FakePageData& fp_data,
                                   _In_ EptData* ept_data);

static void FppDisableFakePage(_In_ const FakePageData& fp_data,
                               _In_ EptData* ept_data);

static void FppSetMonitorTrapFlag(_In_ ProcessorFakePageData* processor_fp_data,
                                  _In_ bool enable);

static void FppSaveLastFakePageData(
    _In_ ProcessorFakePageData* processor_fp_data,
    _In_ const FakePageData& fp_data);

static const FakePageData* FppRestoreLastFakePageData(
    _In_ ProcessorFakePageData* processor_fp_data);

static bool FppIsFuActive(_In_ const SharedFakePageData* shared_fp_data);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, FpAllocateProcessorData)
#pragma alloc_text(INIT, FpAllocateSharedProcessorData)
#pragma alloc_text(PAGE, FpFreeProcessorData)
#pragma alloc_text(PAGE, FpFreeSharedProcessorData)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Allocates per-processor fake page data
_Use_decl_annotations_ EXTERN_C ProcessorFakePageData*
FpAllocateProcessorData() {
  PAGED_CODE();

  auto processor_fp_data = reinterpret_cast<ProcessorFakePageData*>(
      ExAllocatePoolWithTag(NonPagedPool, sizeof(ProcessorFakePageData),
                            kHyperPlatformCommonPoolTag));
  if (!processor_fp_data) {
    return nullptr;
  }
  RtlFillMemory(processor_fp_data, sizeof(ProcessorFakePageData), 0);
  return processor_fp_data;
}

// Frees per-processor fake page data
_Use_decl_annotations_ EXTERN_C void FpFreeProcessorData(
    ProcessorFakePageData* processor_fp_data) {
  PAGED_CODE();

  ExFreePoolWithTag(processor_fp_data, kHyperPlatformCommonPoolTag);
}

// Allocates processor-shared fake page data
_Use_decl_annotations_ EXTERN_C SharedFakePageData*
FpAllocateSharedProcessorData() {
  PAGED_CODE();

  return new SharedFakePageData();
}

// Frees processor-shared fake page data
_Use_decl_annotations_ EXTERN_C void FpFreeSharedProcessorData(
    SharedFakePageData* shared_fp_data) {
  PAGED_CODE();

  delete shared_fp_data;
}

//
// Following code is executed in hypervisor context
//

// Handles MTF VM-exit
_Use_decl_annotations_ void FpHandleMonitorTrapFlag(
    ProcessorFakePageData* processor_fp_data,
    const SharedFakePageData* shared_fp_data, EptData* ept_data) {
  NT_VERIFY(FppIsFuActive(shared_fp_data));

  // Re-enable the shadow hook and clears MTF
  const auto fp_data = FppRestoreLastFakePageData(processor_fp_data);
  FppEnableFakePageForExec(*fp_data, ept_data);
  FppSetMonitorTrapFlag(processor_fp_data, false);
}

// Handles EPT violation VM-exit
_Use_decl_annotations_ void FpHandleEptViolation(
    ProcessorFakePageData* processor_fp_data,
    const SharedFakePageData* shared_fp_data, EptData* ept_data,
    void* fault_va) {
  if (!FppIsFuActive(shared_fp_data)) {
    return;
  }

  const auto fp_data = FppFindFakePageDataByPage(shared_fp_data, fault_va);
  if (!fp_data) {
    return;
  }

  // EPT violation was caused because a guest tried to read or write to a page
  // where currently set as execute only. Let a guest read or write the page
  // from a read/write fake page and run a single instruction.
  FppEnableFakePageForRw(*fp_data, ept_data);
  FppSetMonitorTrapFlag(processor_fp_data, true);
  FppSaveLastFakePageData(processor_fp_data, *fp_data);
}

// Create fake page data without activating it
_Use_decl_annotations_ bool FpVmCallCreateFakePage(
    SharedFakePageData* shared_fp_data, void* context) {
  auto fp_data = FppCreateFakePageData(shared_fp_data, context);
  if (!fp_data) {
    return false;
  }

  HYPERPLATFORM_LOG_DEBUG("CR3 = %p, Patch = %p (%p), Exec = %p (%p)",
                          fp_data->target_cr3, fp_data->patch_address,
                          fp_data->pa_base_for_rw,
                          fp_data->shadow_page_base_for_exec->address +
                              BYTE_OFFSET(fp_data->patch_address),
                          fp_data->pa_base_for_exec);

  // FIXME: lock here
  shared_fp_data->all_fp_data.push_back(std::move(fp_data));
  return true;
}

// Creates or reuses a couple of copied pages and initializes FakePageData
_Use_decl_annotations_ static std::unique_ptr<FakePageData>
FppCreateFakePageData(SharedFakePageData* shared_fp_data, void* context) {
  typedef struct {
    ULONG64 start_address;
    ULONG64 original_byte_size;
    std::array<UCHAR, 32> original_bytes;
  } APIMON_CREATE_SHADOW_PARAMETERS;
  C_ASSERT(sizeof(APIMON_CREATE_SHADOW_PARAMETERS) == 48);

  APIMON_CREATE_SHADOW_PARAMETERS params = {};

  const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
  const auto vmm_cr3 = __readcr3();

  // Get parameters from an user supplied address.
  //
  // This is bad code for numerous reasons. What if the context points
  // to an unmapped address? What if the address was already paged-out? What if
  // start_address points to the kernel address space? This code does not give
  // good answers to those situations. A right thing to do is reading the
  // parameter from kernel context where MmProbeAndLockPages() and
  // MmGetSystemAddressForMdlSafe() are avaialable or using Buffered I/O via
  // IOCTL, and then vefity that start_address points to a valid location. See
  // "User-Mode Interactions: Guidelines for Kernel-Mode Drivers" from
  // Microsoft.
  __writecr3(guest_cr3);
  RtlCopyMemory(&params, context, sizeof(params));

  // Get PA of the start_address in requester process's context
  const auto page_base = PAGE_ALIGN(params.start_address);
  const auto pa_base = UtilPaFromVa(page_base);
  __writecr3(vmm_cr3);

  auto fp_data = std::make_unique<FakePageData>();
  fp_data->patch_address = reinterpret_cast<void*>(params.start_address);
  fp_data->target_cr3 = guest_cr3;

  auto reusable_fp_data = FppFindFakePageDataByPage(
      shared_fp_data, reinterpret_cast<void*>(params.start_address));
  if (reusable_fp_data) {
    // Found an existing FakePageData object targetting the same page as this
    // one. re-use shadow pages.
    fp_data->shadow_page_base_for_exec =
        reusable_fp_data->shadow_page_base_for_exec;
  } else {
    // No associated FakePageData for the address. Create a fake page.
    fp_data->shadow_page_base_for_exec = std::make_shared<Page>();
    __writecr3(fp_data->target_cr3);
    RtlCopyMemory(fp_data->shadow_page_base_for_exec->address, page_base,
                  PAGE_SIZE);
    __writecr3(vmm_cr3);
  }
  fp_data->original_bytes = params.original_bytes;
  fp_data->pa_base_for_rw = pa_base;
  fp_data->pa_base_for_exec =
      UtilPaFromVa(fp_data->shadow_page_base_for_exec->address);
  return fp_data;
}

// Find a FakePageData instance by address
_Use_decl_annotations_ static FakePageData* FppFindFakePageDataByPage(
    const SharedFakePageData* shared_fp_data, void* address) {
  const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
  const auto found = std::find_if(
      shared_fp_data->all_fp_data.cbegin(), shared_fp_data->all_fp_data.cend(),
      [address, guest_cr3](const auto& fp_data) {
        return PAGE_ALIGN(fp_data->patch_address) == PAGE_ALIGN(address) &&
               fp_data->target_cr3 == guest_cr3;
      });
  if (found == shared_fp_data->all_fp_data.cend()) {
    return nullptr;
  }
  return found->get();
}

// Enables all fake pages for the current process
_Use_decl_annotations_ NTSTATUS FpVmCallEnableFakePages(
    EptData* ept_data, const SharedFakePageData* shared_fp_data) {
  const auto requester_cr3 = UtilVmRead(VmcsField::kGuestCr3);
  const auto vmm_cr3 = __readcr3();

  // conceal contents of the original PA
  Cr0 cr0_old = {__readcr0()};
  Cr0 cr0_new = cr0_old;
  cr0_new.fields.wp = false;
  __writecr0(cr0_new.all);

  for (auto& fp_data : shared_fp_data->all_fp_data) {
    if (fp_data->target_cr3 != requester_cr3) {
      continue;
    }

    __writecr3(fp_data->target_cr3);
    RtlCopyMemory(fp_data->patch_address, fp_data->original_bytes.data(),
                  fp_data->original_bytes.size());
    __writecr3(vmm_cr3);

    HYPERPLATFORM_LOG_DEBUG_SAFE("Shadowing %p", fp_data->target_cr3,
                                 fp_data->patch_address);
    FppEnableFakePageForExec(*fp_data, ept_data);
  }
  __writecr0(cr0_old.all);
  return STATUS_SUCCESS;
}

// Show a shadowed page for execution
_Use_decl_annotations_ static void FppEnableFakePageForExec(
    const FakePageData& fp_data, EptData* ept_data) {
  const auto old_cr3 = __readcr3();
  __writecr3(fp_data.target_cr3);

  const auto ept_pt_entry =
      EptGetEptPtEntry(ept_data, UtilPaFromVa(fp_data.patch_address));

  // Allow the VMM to redirect read and write access to the address by dening
  // those accesses and handling them on EPT violation
  ept_pt_entry->fields.write_access = false;
  ept_pt_entry->fields.read_access = false;

  // Only execution is allowed on the adresss. Show the copied page for exec
  // that has an actual breakpoint to the guest.
  ept_pt_entry->fields.physial_address =
      UtilPfnFromPa(fp_data.pa_base_for_exec);

  __writecr3(old_cr3);
  UtilInveptAll();
}

// Show a shadowed page for read and write
_Use_decl_annotations_ static void FppEnableFakePageForRw(
    const FakePageData& fp_data, EptData* ept_data) {
  const auto old_cr3 = __readcr3();
  __writecr3(fp_data.target_cr3);

  // Allow a guest to read and write as well as execute the address. Show the
  // copied page for read/write that does not have an breakpoint but reflects
  // all modification by a guest if that happened.
  const auto ept_pt_entry =
      EptGetEptPtEntry(ept_data, UtilPaFromVa(fp_data.patch_address));
  ept_pt_entry->fields.write_access = true;
  ept_pt_entry->fields.read_access = true;
  ept_pt_entry->fields.physial_address = UtilPfnFromPa(fp_data.pa_base_for_rw);

  __writecr3(old_cr3);
  UtilInveptAll();
}

// Disables all fake pages for the current process
_Use_decl_annotations_ void FpVmCallDisableFakePages(
    EptData* ept_data, SharedFakePageData* shared_fp_data) {
  const auto requester_cr3 = UtilVmRead(VmcsField::kGuestCr3);
  const auto vmm_cr3 = __readcr3();

  Cr0 cr0_old = {__readcr0()};
  Cr0 cr0_new = cr0_old;
  cr0_new.fields.wp = false;
  __writecr0(cr0_new.all);

  for (auto& fp_data : shared_fp_data->all_fp_data) {
    if (fp_data->target_cr3 != requester_cr3) {
      continue;
    }

    HYPERPLATFORM_LOG_DEBUG_SAFE("Unshadowing %p", fp_data->target_cr3,
                                 fp_data->patch_address);
    FppDisableFakePage(*fp_data, ept_data);

    // Write back contents of EXEC page onto a patched address
    __writecr3(fp_data->target_cr3);
    RtlCopyMemory(fp_data->patch_address,
                  fp_data->shadow_page_base_for_exec->address +
                      BYTE_OFFSET(fp_data->patch_address),
                  fp_data->original_bytes.size());
    __writecr3(vmm_cr3);
  }
  __writecr0(cr0_old.all);
}

// Stop showing a shadow page
_Use_decl_annotations_ static void FppDisableFakePage(
    const FakePageData& fp_data, EptData* ept_data) {
  const auto old_cr3 = __readcr3();
  __writecr3(fp_data.target_cr3);

  const auto page_base = (UCHAR*)PAGE_ALIGN(fp_data.patch_address);
  const auto pa_base = UtilPaFromVa(page_base);
  const auto ept_pt_entry = EptGetEptPtEntry(ept_data, pa_base);
  ept_pt_entry->fields.write_access = true;
  ept_pt_entry->fields.read_access = true;
  ept_pt_entry->fields.physial_address = UtilPfnFromPa(pa_base);

  __writecr3(old_cr3);
  UtilInveptAll();
}

_Use_decl_annotations_ void FpVmCallDeleteFakePages(
    SharedFakePageData* shared_fp_data) {
  const auto requester_cr3 = UtilVmRead(VmcsField::kGuestCr3);

  // FIXME: lock the structure
  const auto new_end = std::remove_if(
      shared_fp_data->all_fp_data.begin(), shared_fp_data->all_fp_data.end(),
      [requester_cr3](auto& fp_data) {
        return fp_data->target_cr3 == requester_cr3;
      });
  shared_fp_data->all_fp_data.erase(new_end, shared_fp_data->all_fp_data.end());
}

// Set MTF on the current processor
_Use_decl_annotations_ static void FppSetMonitorTrapFlag(
    ProcessorFakePageData* processor_fp_data, bool enable) {
  UNREFERENCED_PARAMETER(processor_fp_data);

  VmxProcessorBasedControls vm_procctl = {
      static_cast<unsigned int>(UtilVmRead(VmcsField::kCpuBasedVmExecControl))};
  vm_procctl.fields.monitor_trap_flag = enable;
  UtilVmWrite(VmcsField::kCpuBasedVmExecControl, vm_procctl.all);
}

// Saves FakePageData as the last one for reusing it on up coming MTF VM-exit
_Use_decl_annotations_ static void FppSaveLastFakePageData(
    ProcessorFakePageData* processor_fp_data, const FakePageData& fp_data) {
  NT_ASSERT(!processor_fp_data->last_fp_data);
  processor_fp_data->last_fp_data = &fp_data;
}

// Retrieves the last FakePageData
_Use_decl_annotations_ static const FakePageData* FppRestoreLastFakePageData(
    ProcessorFakePageData* processor_fp_data) {
  NT_ASSERT(processor_fp_data->last_fp_data);
  auto fp_data = processor_fp_data->last_fp_data;
  processor_fp_data->last_fp_data = nullptr;
  return fp_data;
}

// Checks if DdiMon is already initialized
_Use_decl_annotations_ static bool FppIsFuActive(
    const SharedFakePageData* shared_fp_data) {
  return !!(shared_fp_data);
}
