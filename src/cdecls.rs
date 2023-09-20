// Copyright (c) 2023 Daniel Fox Franke
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

use std::ffi::{c_int, c_short, c_void};

#[non_exhaustive]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Subtype code for SIGILL.
pub enum SigillCode {
    /// Illegal opcode.
    ILLOPC,
    /// Illegal operand.
    ILLOPN,
    /// Illegal addressing mode.
    ILLADR,
    /// Illegal trap.
    ILLTRP,
    /// Privileged opcode.
    PRVOPC,
    /// Privileged register.
    PRVREG,
    /// Coprocessor error.
    CORPOC,
    /// Internal stack error.
    BADSTK,
}

#[non_exhaustive]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Subtype code for SIGFPE.
pub enum SigfpeCode {
    /// Integer divide by zero.
    INTDIV,
    /// Integer overflow.
    INTOVF,
    /// Floating-point divide by zero.
    FLTDIV,
    /// Floating-point overflow.
    FLTOVF,
    /// Floating-point underflow.
    FLTUND,
    /// Floating-point inexact result.
    FLTRES,
    /// Floating-point invalid operation.
    FLTINV,
    /// Subscript out of range.
    FLTSUB,
}

#[non_exhaustive]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Subtype code for SIGSEGV.
pub enum SigsegvCode {
    /// Address not mapped to object.
    MAPERR,
    /// Invalid permissions for mapped object.
    ACCERR,
    /// Failed address bound checks.
    BNDERR,
    /// Access was denied by memory protection keys.
    PKUERR,
}

#[non_exhaustive]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
/// Subtype code for SIGBUS.
pub enum SigbusCode {
    /// Invalid address alignment.
    ADRALN,
    /// Nonexistent physical address.
    ADDERR,
    /// Object-specific hardware error.
    OBJERR,
    /// Hardware memory error consumed on a machine check; action required.
    MCEERR_AR,
    /// Hardware memory error detected in process but not consumed; action optional.
    MCEERR_AO,
}

#[non_exhaustive]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Subtype code for SIGTRAP.
pub enum SigtrapCode {
    /// Process breakpoint.
    BRKPT,
    /// Process trace trap.
    TRACE,
    /// Process taken branch trap (IA-64 only).
    BRANCH,
    /// Hardware breakpoint/watchpoint (IA-64 only).
    HWBKPT,
}

extern "C" {
    pub(crate) fn hwexception_catch(
        callback: unsafe extern "C" fn(*mut c_void),
        context: *mut c_void,
        exception: *mut c_void,
        jmp_buf_ptr: *mut *mut c_void,
        err_buf_ptr: *mut *mut c_void,
    ) -> c_int;

    pub(crate) fn hwexception_throw(
        exception: *const c_void,
        exception_len: usize,
        jmp_buf_ptr: *mut *mut c_void,
        err_buf_ptr: *mut *mut c_void,
    );

    pub(crate) fn hwexception_translate_sigill_code(
        out: *mut SigillCode,
        code: c_int,
    ) -> c_int;
    pub(crate) fn hwexception_translate_sigfpe_code(
        out: *mut SigfpeCode,
        code: c_int,
    ) -> c_int;
    pub(crate) fn hwexception_translate_sigsegv_code(
        out: *mut SigsegvCode,
        code: c_int,
    ) -> c_int;
    pub(crate) fn hwexception_translate_sigbus_code(
        out: *mut SigbusCode,
        code: c_int,
    ) -> c_int;
    pub(crate) fn hwexception_translate_sigtrap_code(
        out: *mut SigtrapCode,
        code: c_int,
    ) -> c_int;

    pub(crate) fn hwexception_get_ip(context: *const c_void) -> *mut c_void;
    pub(crate) fn hwexception_get_sp(context: *const c_void) -> *mut c_void;
    pub(crate) fn hwexception_get_symbol_address(context: *const c_void) -> *mut c_void;

    pub(crate) fn hwexception_get_addr_lsb(info: *const libc::siginfo_t) -> c_short;
    pub(crate) fn hwexception_get_lower(info: *const libc::siginfo_t) -> *mut c_void;
    pub(crate) fn hwexception_get_upper(info: *const libc::siginfo_t) -> *mut c_void;
    pub(crate) fn hwexception_get_pkey(info: *const libc::siginfo_t) -> c_int;
}
