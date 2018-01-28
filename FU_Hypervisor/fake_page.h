// Copyright (c) 2015-2018, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to fake page functions.

#ifndef FU_HYPERVISOR_FAKE_PAGE_H_
#define FU_HYPERVISOR_FAKE_PAGE_H_

#include <fltKernel.h>

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

struct EptData;
struct ProcessorFakePageData;
struct SharedFakePageData;

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    ProcessorFakePageData* FpAllocateProcessorData();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    void FpFreeProcessorData(_In_ ProcessorFakePageData* processor_fp_data);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    SharedFakePageData* FpAllocateSharedProcessorData();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    void FpFreeSharedProcessorData(_In_ SharedFakePageData* shared_fp_data);

_IRQL_requires_min_(DISPATCH_LEVEL) void FpHandleMonitorTrapFlag(
    _In_ ProcessorFakePageData* processor_fp_data,
    _In_ const SharedFakePageData* shared_fp_data, _In_ EptData* ept_data);

_IRQL_requires_min_(DISPATCH_LEVEL) void FpHandleEptViolation(
    _In_ ProcessorFakePageData* processor_fp_data,
    _In_ const SharedFakePageData* shared_fp_data, _In_ EptData* ept_data,
    _In_ void* fault_va);

_IRQL_requires_max_(PASSIVE_LEVEL) bool FpVmCallCreateFakePage(
    _In_ SharedFakePageData* shared_fp_data, _In_ void* context);

_IRQL_requires_min_(DISPATCH_LEVEL) NTSTATUS
    FpVmCallEnableFakePages(_In_ EptData* ept_data,
                            _In_ const SharedFakePageData* shared_fp_data);

_IRQL_requires_min_(DISPATCH_LEVEL) void FpVmCallDisableFakePages(
    _In_ EptData* ept_data, _In_ SharedFakePageData* shared_fp_data);

_IRQL_requires_min_(DISPATCH_LEVEL) void FpVmCallDeleteFakePages(
    _In_ SharedFakePageData* shared_fp_data);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

#endif  // FU_HYPERVISOR_FAKE_PAGE_H_
