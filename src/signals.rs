// Copyright (c) 2023 Daniel Fox Franke
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

use crate::cdecls::*;

use std::any::Any;
use std::ffi::{c_int, c_short, c_void};
use std::marker::PhantomData;
use std::mem::MaybeUninit;

///Error on unsupported signal number or code.
///
/// This can be returned by the `from_raw` constructor of [`Signo`] or
/// [`Signal`] when the signal number or the subtype code is not one that is
/// supported by this crate.
#[derive(Debug, Copy, Clone)]
pub enum UnsupportedSignalError {
    /// The signal number is not supported.
    UnsupportedSigno {
        /// Signal number.
        signo: c_int,
    },
    /// The signal number is supported, but the code is not.
    UnsupportedCode {
        /// Signal number.
        signo: c_int,
        /// Signal code.
        code: c_int,
    },
}

impl std::fmt::Display for UnsupportedSignalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnsupportedSignalError::UnsupportedSigno { signo } => {
                write!(f, "Unsupported signal number: signo={}", signo)
            }
            UnsupportedSignalError::UnsupportedCode { signo, code } => {
                write!(f, "Unsupported signal code: signo={}, code={}", signo, code)
            }
        }
    }
}

impl std::error::Error for UnsupportedSignalError {}

#[non_exhaustive]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Signal numbers that this crate supports handling.
pub enum Signo {
    /// Illegal instruction.
    /// 
    /// Note that Rust's `abort` intrinsic works by executing an illegal instruction.
    /// Be sure when handling this signal that your hook's behavior does not conflict
    /// with this intent.
    SIGILL,
    /// Floating point exception.
    SIGFPE,
    /// Segmentation fault.
    SIGSEGV,
    /// Bus error.
    SIGBUS,
    /// Trace/breakpoint trap.
    SIGTRAP,
}

impl Signo {
    /// Returns a list of all signal numbers supported by this crate.
    pub const fn all() -> &'static [Signo] {
        use Signo::*;
        &[SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP]
    }

    /// Constructs a `Signo` from a raw signal number.
    pub fn from_raw(raw: c_int) -> Result<Signo, UnsupportedSignalError> {
        match raw {
            libc::SIGILL => Ok(Signo::SIGILL),
            libc::SIGFPE => Ok(Signo::SIGFPE),
            libc::SIGSEGV => Ok(Signo::SIGSEGV),
            libc::SIGBUS => Ok(Signo::SIGBUS),
            libc::SIGTRAP => Ok(Signo::SIGTRAP),
            _ => Err(UnsupportedSignalError::UnsupportedSigno { signo: raw }),
        }
    }
}

impl From<Signo> for c_int {
    fn from(value: Signo) -> Self {
        match value {
            Signo::SIGILL => libc::SIGILL,
            Signo::SIGFPE => libc::SIGFPE,
            Signo::SIGSEGV => libc::SIGSEGV,
            Signo::SIGBUS => libc::SIGBUS,
            Signo::SIGTRAP => libc::SIGTRAP,
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Signal number plus associated subtype code.
pub enum Signal {
    /// Illegal instruction.
    Ill(SigillCode),
    /// Floating point exception.
    Fpe(SigfpeCode),
    /// Segmentation fault.
    Segv(SigsegvCode),
    /// Bus error.
    Bus(SigbusCode),
    /// Trace/breakpoint trap.
    Trap(SigtrapCode),
}

impl Signal {
    /// Constructs a `Signal` from a raw signal number and subtype code.
    pub fn from_raw(signo: c_int, code: c_int) -> Result<Signal, UnsupportedSignalError> {
        let cooked_signo = Signo::from_raw(signo)?;
        let err = UnsupportedSignalError::UnsupportedCode { signo, code };

        match cooked_signo {
            Signo::SIGILL => unsafe {
                let mut cooked_code: MaybeUninit<SigillCode> = MaybeUninit::uninit();
                let ret = hwexception_translate_sigill_code(cooked_code.as_mut_ptr(), code);
                if ret == 1 {
                    Ok(Signal::Ill(cooked_code.assume_init()))
                } else {
                    Err(err)
                }
            },
            Signo::SIGFPE => unsafe {
                let mut cooked_code: MaybeUninit<SigfpeCode> = MaybeUninit::uninit();
                let ret = hwexception_translate_sigfpe_code(cooked_code.as_mut_ptr(), code);
                if ret == 1 {
                    Ok(Signal::Fpe(cooked_code.assume_init()))
                } else {
                    Err(err)
                }
            },
            Signo::SIGSEGV => unsafe {
                let mut cooked_code: MaybeUninit<SigsegvCode> = MaybeUninit::uninit();
                let ret = hwexception_translate_sigsegv_code(cooked_code.as_mut_ptr(), code);
                if ret == 1 {
                    Ok(Signal::Segv(cooked_code.assume_init()))
                } else {
                    Err(err)
                }
            },
            Signo::SIGBUS => unsafe {
                let mut cooked_code: MaybeUninit<SigbusCode> = MaybeUninit::uninit();
                let ret = hwexception_translate_sigbus_code(cooked_code.as_mut_ptr(), code);
                if ret == 1 {
                    Ok(Signal::Bus(cooked_code.assume_init()))
                } else {
                    Err(err)
                }
            },
            Signo::SIGTRAP => unsafe {
                let mut cooked_code: MaybeUninit<SigtrapCode> = MaybeUninit::uninit();
                let ret = hwexception_translate_sigtrap_code(cooked_code.as_mut_ptr(), code);
                if ret == 1 {
                    Ok(Signal::Trap(cooked_code.assume_init()))
                } else {
                    Err(err)
                }
            },
        }
    }

    /// Returns the signal number associated with this signal.
    pub fn signo(self) -> Signo {
        use Signal::*;
        match self {
            Ill(_) => Signo::SIGILL,
            Fpe(_) => Signo::SIGFPE,
            Segv(_) => Signo::SIGSEGV,
            Bus(_) => Signo::SIGBUS,
            Trap(_) => Signo::SIGTRAP,
        }
    }
}

#[derive(Debug,Clone)]
enum ExceptionInfoImpl<'a> {
    Borrowed {
        signo: c_int,
        siginfo: *mut libc::siginfo_t,
        context: *mut c_void,
        _phantom: PhantomData<&'a ()>,
    },
    Owned {
        signo: c_int,
        siginfo: libc::siginfo_t,
        context: *mut c_void,
        sp: *mut c_void,
        ip: *mut c_void,
        symbol_address: *mut c_void,
    },
}

#[derive(Debug,Clone)]
/// Information about an exception.
pub struct ExceptionInfo<'a>(ExceptionInfoImpl<'a>);

impl ExceptionInfo<'_> {
    /// Construct from arguments passed to a POSIX signal handler.
    ///
    /// # Safety
    /// The caller must ensure the validity of the pointers and limit the
    /// lifetime of the `ExceptionInfo` structure to that of the pointers. On
    /// platforms which have a `ucontext_t` type, `context` must point to
    /// one or else be NULL.
    pub unsafe fn new<'a>(
        signo: c_int,
        siginfo: *mut libc::siginfo_t,
        context: *mut c_void,
    ) -> ExceptionInfo<'a> {
        ExceptionInfo(ExceptionInfoImpl::Borrowed {
            signo,
            siginfo,
            context,
            _phantom: PhantomData,
        })
    }

    /// Converts `self` into a representation which owns its storage.
    pub fn into_owned(self) -> ExceptionInfo<'static> {
        ExceptionInfo(match self.0 {
            ExceptionInfoImpl::Borrowed {
                signo,
                siginfo,
                context,
                ..
            } => unsafe {
                ExceptionInfoImpl::Owned {
                    signo,
                    siginfo: *siginfo,
                    context,
                    sp: hwexception_get_sp(context),
                    ip: hwexception_get_ip(context),
                    symbol_address: hwexception_get_symbol_address(context),
                }
            },
            ExceptionInfoImpl::Owned {
                signo,
                siginfo,
                context,
                sp,
                ip,
                symbol_address,
            } => ExceptionInfoImpl::Owned {
                signo,
                siginfo,
                context,
                sp,
                ip,
                symbol_address
            },
        })
    }

    /// Returns the raw signal number which was passed to the signal handler.
    pub fn signo_raw(&self) -> c_int {
        match &self.0 {
            ExceptionInfoImpl::Borrowed { signo, .. } => *signo,
            ExceptionInfoImpl::Owned { signo, .. } => *signo,
        }
    }

    /// Returns a reference to the raw `siginfo_t` structure which was passed to
    /// the signal handler.
    pub fn signinfo_raw(&self) -> &libc::siginfo_t {
        match &self.0 {
            ExceptionInfoImpl::Borrowed { siginfo, .. } => unsafe { &**siginfo },
            ExceptionInfoImpl::Owned { siginfo, .. } => siginfo,
        }
    }

    /// Returns the context pointer which was passed to the signal handler.
    pub fn context(&self) -> *mut c_void {
        match &self.0 {
            ExceptionInfoImpl::Borrowed { context, .. } => *context,
            ExceptionInfoImpl::Owned { context, .. } => *context,
        }
    }

    /// Returns the type of signal which triggered this exception.
    pub fn signo(&self) -> Signo {
        Signo::from_raw(self.signo_raw()).unwrap()
    }

    /// Returns the address of the memory access which triggered the exception.
    pub fn addr(&self) -> *mut c_void {
        unsafe { self.signinfo_raw().si_addr() }
    }

    /// Returns the type of signal which triggered this exception along with its
    /// associated subtype.
    ///
    /// This method is guaranteed to succeed when called on an `ExceptionInfo`
    /// which was passed to a registered hook by a signal handler which was
    /// installed by this crate.
    pub fn signal(&self) -> Result<Signal, UnsupportedSignalError> {
        Signal::from_raw(self.signo_raw(), self.signinfo_raw().si_code)
    }

    /// For SIGBUS signals of subtype `MCEERR_AO` or `MCEERR_AR`, this returns
    /// an indication the least significant bit of the reported address and
    /// therefore the extent of the corruption. For example, if a full page is
    /// corrupted, this returns `log2(sysconf(_SC_PAGESIZE))`.
    ///
    /// For all other signals and subtypes, this returns `None`.
    pub fn addr_lsb(&self) -> Option<c_short> {
        match self.signal().ok()? {
            Signal::Bus(SigbusCode::MCEERR_AO | SigbusCode::MCEERR_AR) => unsafe {
                Some(hwexception_get_addr_lsb(self.signinfo_raw()))
            },
            _ => None,
        }
    }

    /// For SIGSEGV signals of subtype `BNDERR`, this returns the lower bound of
    /// the failed bounds check. Otherwise it returns `None`.
    pub fn lower(&self) -> Option<*mut c_void> {
        match self.signal().ok()? {
            Signal::Segv(SigsegvCode::BNDERR) => unsafe {
                Some(hwexception_get_lower(self.signinfo_raw()))
            },
            _ => None,
        }
    }

    /// For SIGSEGV signals of subtype `BNDERR`, this returns the upper bound of
    /// the failed bounds check. Otherwise it returns `None`.
    pub fn upper(&self) -> Option<*mut c_void> {
        match self.signal().ok()? {
            Signal::Segv(SigsegvCode::BNDERR) => unsafe {
                Some(hwexception_get_upper(self.signinfo_raw()))
            },
            _ => None,
        }
    }

    /// For SIGSEGV signals of subtype `PKUERR`, this returns the protection key on
    /// the page table entry (PTE) which caused the exception.
    pub fn pkey(&self) -> Option<c_int> {
        match self.signal().ok()? {
            Signal::Segv(SigsegvCode::PKUERR) => unsafe {
                Some(hwexception_get_pkey(self.signinfo_raw()))
            },
            _ => None,
        }
    }

    /// Returns the contents of the stack pointer register at the time of the
    /// exception.
    /// 
    /// Not supported on all platforms. If unsupported, returns null. Adding
    /// support for new platforms is usually straightforward; please file an
    /// issue if you want something added.
    pub fn sp(&self) -> *mut c_void {
        match &self.0 {
            ExceptionInfoImpl::Borrowed { context, .. } => unsafe {
                hwexception_get_sp(*context)
            }
            ExceptionInfoImpl::Owned { sp, .. } => *sp,
        }
    }

    /// Returns the address of the instruction which triggered the exception.
    /// 
    /// Not supported on all platforms. If unsupported, returns null. Adding
    /// support for new platforms is usually straightforward; please file an
    /// issue if you want something added.
    pub fn ip(&self) -> *mut c_void {
        match &self.0 {
            ExceptionInfoImpl::Borrowed { context, .. } => unsafe {
                hwexception_get_ip(*context)
            }
            ExceptionInfoImpl::Owned { ip, .. } => *ip,
        }
    }

    /// Returns the starting symbol address of the function which triggered the
    /// exception.
    /// 
    /// Not supported on all platforms. If unsupported, returns null. Adding
    /// support for new platforms is usually straightforward; please file an
    /// issue if you want something added.
    pub fn symbol_address(&self) -> *mut c_void {
        match &self.0 {
            ExceptionInfoImpl::Borrowed { context, .. } => unsafe {
                hwexception_get_symbol_address(*context)
            }
            ExceptionInfoImpl::Owned { symbol_address, .. } => *symbol_address,
        }
    }
}

#[derive(Debug)]
/// Exception information plus optional additional payload.
pub struct ExtExceptionInfo {
    info: Box<ExceptionInfo<'static>>,
    additional: Option<Box<dyn Any + 'static>>,
}

impl ExtExceptionInfo {
    /// Returns the exception information.
    pub fn info(&self) -> &ExceptionInfo<'static> {
        self.info.as_ref()
    }
    /// Returns an optional additional payload.
    pub fn additional(&self) -> Option<&(dyn Any + 'static)> {
        self.additional.as_ref().map(|b| b.as_ref())
    }
}

impl From<ExceptionInfo<'_>> for ExtExceptionInfo {
    fn from(info: ExceptionInfo<'_>) -> Self {
        ExtExceptionInfo {
            info: Box::new(info.into_owned()),
            additional: None,
        }
    }
}

impl<A> From<(ExceptionInfo<'_>, A)> for ExtExceptionInfo
where
    A: 'static,
{
    fn from(val: (ExceptionInfo<'_>, A)) -> Self {
        ExtExceptionInfo {
            info: Box::new(val.0.into_owned()),
            additional: Some(Box::new(val.1)),
        }
    }
}