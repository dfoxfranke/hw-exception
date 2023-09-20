// Copyright (c) 2023 Daniel Fox Franke
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#![warn(missing_docs)]
//! This crate handles POSIX signals which are triggered in response to hardware
//! exceptions. These signals include:
//!
//! * `SIGILL`
//! * `SIGFPE`
//! * `SIGSEGV`
//! * `SIGBUS`
//! * `SIGTRAP`
//!
//! Examples of hardware exceptions which trigger them include:
//!
//! * Illegal instructions
//! * General protection faults
//! * Divide-by-zero errors
//! * Floating point exceptions
//! * Page faults
//! * General protection faults
//! * Machine check exceptions (raised, *e.g.*, on double-bit errors from ECC
//!   memory)
//! * Hardware breakpoints
//!
//! Normally, receiving any of these signals indicates either a hardware failure
//! or certain kinds of bugs which shouldn't be possible in safe Rust code. When
//! they're received unexpectedly, the only sensible way to proceed is to abort
//! the process and dump core, which is exactly what would normally happen.
//! However, many use cases exist where such signals are expected, and recovery
//! is possible. Here are just a few:
//!
//! * **Stop-and-copy garbage collectors**. Certain garbage-collection
//!   techniques routinely trigger segmentation faults. The signal handler can
//!   map a valid page into the faulting address and then execution can resume
//!   where it left off. (Consider the
//!   [`userfaultfd`](https://docs.rs/userfaultfd) crate as an alternative for
//!   this and similar use cases.)
//! * **Sharing memory with untrusted peers**. Writers to a shared memory
//!   segment can do various unfriendly things, such as truncating it
//!   unexpectedly, which will cause other processes accessing the segment to
//!   get a `SIGBUS`, which they can't guard against without running into TOCTOU
//!   problems. Victims of such behavior can catch the signal and jump back to a
//!   recovery point. (Consider the [`memfd`](https://docs.rs/memfd) crate as an
//!   alternative to avoid such complications.)
//! * **Fancy numerical stuff**. Sometimes it's more efficient to let a
//!   divide-by-zero or a floating point exception occur than it is to check
//!   every operation which might trigger it.
//! * **Robust storage layers**. As the size of disk or memory approaches
//!   infinity, the probability of a hardware error approaches one. Catching
//!   machine check exceptions makes it possible to handle such failures
//!   robustly by switching to redundant storage or by tolerating small amounts
//!   of data loss.
//! * **Debuggers**, which will get a `SIGTRAP` upon hitting a breakpoint
//!   they've set.
//! 
//! Hardware exceptions are generally handled in one of three ways; this crate
//! supports all of them to varying degrees. They are:
//! 
//! * **Patch and continue**: Fix the problem from within the signal handler,
//!   and then return from it to re-execute the excepting instruction. For
//!   example, by mapping a valid page to correct a segmentation fault.
//! * **Catch and recover**: Use `setjmp` to store a recovery point, and then
//!   `longjmp` back to it from the signal handler.
//! * **Scream and die**: Don't attempt to recover from the exception at all;
//!   just use the signal handler to log some diagnostics before aborting.
//! 
//! In all three cases, your first entrypoint into this crate will be the
//! [`register_hook`] function, to which you will provide a callback which
//! receives [`ExceptionInfo`]. For catch-and-recover, you will wrap the
//! potentially-excepting block using [`catch`] and have the hook that you
//! registered call [`throw`].
//! 
//! Hardware exceptions are synchronous signals, which means that the usual
//! cautions about ["signal
//! safety"](https://man7.org/linux/man-pages/man7/signal-safety.7.html) don't
//! apply; you can safely allocate memory, for example. However, do be cautious
//! that signal handlers run an alternate stack which is usually much smaller
//! than the main one, typically 8 KiB, and is easy to overflow by accident. If
//! you find that a `SIGSEGV` hook is mysteriously hanging, it may be that the
//! hook is itself segfaulting due to a stack overflow, resulting in an infinite
//! loop. [`Backtrace`](std::backtrace::Backtrace)'s
//! [`Display`](std::fmt::Display) implementation seems to be particularly
//! stack-hungry, so printing a backtrace from a signal handler is likely to
//! lead to an overflow. Two good ways to get around this are either to
//! [`throw`] the [`Backtrace`](std::backtrace::Backtrace) and print it upon
//! returning from [`catch`], or to spawn a thread from the signal handler and
//! do your work from the child thread.
//! 
//! # Example
//! 
//! The following example triggers a segmentation fault by dereferencing a null
//! pointer, catches and recovers from it, and then prints a backtrace showing
//! where the segfault occurred.
//! 
//! ```
//!   use hw_exception::*;
//!   use std::backtrace::Backtrace;
//! 
//!   unsafe {
//!     // Register a hook for SIGSEGV, which captures and throws a backtrace.
//!     register_hook(&[Signo::SIGSEGV], |e| {
//!       let bt = Backtrace::force_capture();
//!       throw((e, bt))
//!     });
//!   }
//! 
//!   // Dereference a null pointer from within a `catch` block. Using `read_volatile`
//!   // prevents this from being UB.
//!   let result = catch(|| unsafe {
//!      std::ptr::null::<usize>().read_volatile()
//!   });
//! 
//!   // Assert that this block resulted in an exception, and extract it.
//!   let e = result.expect_err("dereferencing a null pointer should have segfaulted, but gave");
//! 
//!   // Extract and print the backtrace
//!   let bt : &Backtrace = e
//!      .additional()
//!      .expect("thrown exception info should have included additional data")
//!      .downcast_ref()
//!      .expect("additional data should have been a `Backtrace`");
//!   println!("{}", bt);
//! ```


mod cdecls;
mod signals;

pub use cdecls::*;
pub use signals::*;
use std::any::Any;
use std::cell::UnsafeCell;
use std::ffi::{c_int, c_void};
use std::mem::ManuallyDrop;
use std::panic::UnwindSafe;
use std::ptr::{addr_of, addr_of_mut};
use std::sync::{Mutex, MutexGuard};


/// A boxed closure which can be invoked in response to an exception being raised.
pub type DynExceptionHook = Box<dyn (Fn(ExceptionInfo<'_>) -> bool) + Send + Sync + 'static>;

#[derive(Debug, Copy, Clone)]
struct ExceptionHookRaw(*const (dyn (Fn(ExceptionInfo<'_>) -> bool) + Send + Sync + 'static));

unsafe impl Send for ExceptionHookRaw {}
unsafe impl Sync for ExceptionHookRaw {}

/// A handle to a registered exception hook.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExceptionHookId(u128); //Make this huge so we never have to think about overflow.

static ID_COUNTER: Mutex<u128> = Mutex::new(0);

static SIGILL_HOOKS: Mutex<Vec<(ExceptionHookId, ExceptionHookRaw)>> = Mutex::new(Vec::new());
static SIGFPE_HOOKS: Mutex<Vec<(ExceptionHookId, ExceptionHookRaw)>> = Mutex::new(Vec::new());
static SIGSEGV_HOOKS: Mutex<Vec<(ExceptionHookId, ExceptionHookRaw)>> = Mutex::new(Vec::new());
static SIGBUS_HOOKS: Mutex<Vec<(ExceptionHookId, ExceptionHookRaw)>> = Mutex::new(Vec::new());
static SIGTRAP_HOOKS: Mutex<Vec<(ExceptionHookId, ExceptionHookRaw)>> = Mutex::new(Vec::new());

static SIGILL_OLDACTION: Mutex<Option<libc::sigaction>> = Mutex::new(None);
static SIGFPE_OLDACTION: Mutex<Option<libc::sigaction>> = Mutex::new(None);
static SIGSEGV_OLDACTION: Mutex<Option<libc::sigaction>> = Mutex::new(None);
static SIGBUS_OLDACTION: Mutex<Option<libc::sigaction>> = Mutex::new(None);
static SIGTRAP_OLDACTION: Mutex<Option<libc::sigaction>> = Mutex::new(None);

thread_local!(static JMP_BUF_PTR: UnsafeCell<*mut c_void> = UnsafeCell::new(std::ptr::null_mut()));
thread_local!(static ERR_BUF_PTR: UnsafeCell<*mut c_void> = UnsafeCell::new(std::ptr::null_mut()));

extern "C" fn run_hooks(
    signo_raw: c_int,
    siginfo: *mut libc::siginfo_t,
    context: *mut c_void,
) -> bool {
    unsafe {
        let signo = if let Ok(signal) = Signal::from_raw(signo_raw, (*siginfo).si_code) {
            signal.signo()
        } else {
            return false;
        };

        let hooks: Vec<_> = lookup_hooks(signo)
            .iter()
            .rev()
            .map(|(_, raw)| raw.0)
            .collect();
        for hook in hooks {
            let exception_info = ExceptionInfo::new(signo_raw, siginfo, context);
            let f = &*hook;
            if f(exception_info) {
                return true;
            }
        }

        false
    }
}

extern "C" fn handler(signo_raw: c_int, siginfo: *mut libc::siginfo_t, context: *mut c_void) {
    if run_hooks(signo_raw, siginfo, context) {
        return;
    }

    let signo = match signo_raw {
        libc::SIGILL => Signo::SIGILL,
        libc::SIGFPE => Signo::SIGFPE,
        libc::SIGSEGV => Signo::SIGSEGV,
        libc::SIGBUS => Signo::SIGBUS,
        libc::SIGTRAP => Signo::SIGTRAP,
        _ => return,
    };

    if let Some(old_action) = *lookup_oldaction(signo) {
        if old_action.sa_sigaction == libc::SIG_DFL {
            unsafe {
                if libc::signal(signo_raw, libc::SIG_DFL) == libc::SIG_ERR {
                    std::process::abort();
                }
            }
        } else if old_action.sa_sigaction == libc::SIG_IGN {
        } else if old_action.sa_flags & libc::SA_SIGINFO != 0 {
            let f: extern "C" fn(c_int, *mut libc::siginfo_t, context: *mut c_void) =
                unsafe { std::mem::transmute(old_action.sa_sigaction) };
            f(signo_raw, siginfo, context);
        } else {
            let f: extern "C" fn(c_int) = unsafe { std::mem::transmute(old_action.sa_sigaction) };
            f(signo_raw);
        }
    }
}

fn lookup_oldaction(signo: Signo) -> MutexGuard<'static, Option<libc::sigaction>> {
    match signo {
        Signo::SIGILL => SIGILL_OLDACTION.lock().unwrap(),
        Signo::SIGFPE => SIGFPE_OLDACTION.lock().unwrap(),
        Signo::SIGSEGV => SIGSEGV_OLDACTION.lock().unwrap(),
        Signo::SIGBUS => SIGBUS_OLDACTION.lock().unwrap(),
        Signo::SIGTRAP => SIGTRAP_OLDACTION.lock().unwrap(),
    }
}

fn lookup_hooks(signo: Signo) -> MutexGuard<'static, Vec<(ExceptionHookId, ExceptionHookRaw)>> {
    match signo {
        Signo::SIGILL => SIGILL_HOOKS.lock().unwrap(),
        Signo::SIGFPE => SIGFPE_HOOKS.lock().unwrap(),
        Signo::SIGSEGV => SIGSEGV_HOOKS.lock().unwrap(),
        Signo::SIGBUS => SIGBUS_HOOKS.lock().unwrap(),
        Signo::SIGTRAP => SIGTRAP_HOOKS.lock().unwrap(),
    }
}

fn register_handler(signo: Signo) {
    let mut old_action_mutex = lookup_oldaction(signo);

    if old_action_mutex.is_some() {
        return;
    }

    unsafe {
        let mut sigset: libc::sigset_t = std::mem::zeroed();
        assert!(libc::sigemptyset(&mut sigset) == 0);
        let mut action: libc::sigaction = std::mem::zeroed();

        let handler_ptr = handler as extern "C" fn(c_int, *mut libc::siginfo_t, *mut c_void);
        action.sa_mask = sigset;
        action.sa_sigaction = handler_ptr as usize;
        action.sa_flags = libc::SA_NODEFER | libc::SA_ONSTACK | libc::SA_SIGINFO;

        let old_action = old_action_mutex.insert(std::mem::zeroed());

        assert!(libc::sigaction(signo.into(), &action, old_action) == 0);
    }
}

fn unregister_handler(signo: Signo) {
    let mut old_handler = lookup_oldaction(signo);

    let action = match old_handler.take() {
        Some(action) => action,
        None => return,
    };

    unsafe {
        assert!(libc::sigaction(signo.into(), &action, std::ptr::null_mut()) == 0);
    }
}

/// Registers a exception hook.
/// 
/// The hook will be invoked from a signal handler when any of the specified
/// signals are raised.
///
/// If multiple exception hooks are registered for one signal, they will be
/// invoked in reverse order of registration until one of them returns `true`.
/// If all hooks return `false`, whatever signal action was installed prior to
/// any hooks being registered will be taken. In the case of the prior signal
/// action being the default signal handler, this is implemented by reinstalling
/// `SIG_DFL` and then returning, which should re-trigger the exception and dump
/// core.
///
/// Hooks will be called only when the signal's subtype code indicates that it
/// was triggered synchronously by a hardware exception. In particular, hooks
/// will *not* run for any signal which was delivered using `kill(2)`. Hooks
/// therefore do not need to worry about async-signal safety and can do things
/// like allocate memory without risking deadlocks.
///
/// The returned [`ExceptionHookId`] can later be used to unregister the hook.
///
/// # Safety
/// *In isolation*, this call is always safe. The function is declared as
/// `unsafe` in order to simplify reasoning about the soundness of unsafe code
/// which potentially triggers exceptions. Making the registration of exception
/// hooks an unsafe operation means that unsafe code can rely on knowing exactly
/// what will happen when an exception occurs, without having to account for the
/// possibility that untrusted safe code may have installed a rogue exception
/// hook.
pub unsafe fn register_hook<S, H>(signals: &S, hook: H) -> ExceptionHookId
where
    S: AsRef<[Signo]> + ?Sized,
    H: for<'a> Fn(ExceptionInfo<'a>) -> bool + Send + Sync + 'static,
{
    let mut counter = ID_COUNTER.lock().unwrap();
    let id = ExceptionHookId(*counter);
    *counter += 1;
    std::mem::drop(counter);

    let raw = ExceptionHookRaw(Box::into_raw(hook.into()));

    for signo in signals.as_ref().iter().copied() {
        let mut hooks = lookup_hooks(signo);
        hooks.push((id, raw));
        register_handler(signo);
    }

    id
}

/// Unregisters an exception hook.
///
/// Returns the exception hook, if found. Calling `unregister_exception_hook`
/// multiple times with the same hook id will result in subsequent calls
/// returning `None`.
///
/// # Safety
/// *In isolation*, this call is always safe. The function is declared as
/// `unsafe` in order to simplify reasoning about the soundness of unsafe code
/// which potentially triggers exceptions. Making unregistration of exception
/// hooks an unsafe operation means that unsafe code can rely on knowing exactly
/// what will happen when a exception occurs, without having to account for the
/// possibility that untrusted safe code may have uninstalled an exception hook
/// it was relying on.
pub unsafe fn unregister_hook(id: ExceptionHookId) -> Option<DynExceptionHook> {
    let mut maybe_raw = None;

    for signo in Signo::all().iter().copied() {
        let mut hooks = lookup_hooks(signo);

        if let Ok(index) = hooks.binary_search_by(|probe| probe.0.cmp(&id)) {
            maybe_raw = Some(hooks.remove(index).1);
            if hooks.is_empty() {
                unregister_handler(signo);
            }
        }
    }

    maybe_raw.map(|raw| Box::from_raw(raw.0.cast_mut()))
}

/// Throws an exception which can be caught by [`catch`].
///
/// If there is no `catch` invocation anywhere on the stack, this
/// functions returns `false`; otherwise, it does not return. It will never
/// return `true`; its return type is `bool` rather than `()` just to make it
/// more ergonomic to use as the final statement of an exception hook.
pub fn throw<F: Into<ExtExceptionInfo>>(exception: F) -> bool {
    let extinfo: ExtExceptionInfo = exception.into();
    JMP_BUF_PTR.with(|jmp_buf| {
        ERR_BUF_PTR.with(|err_buf| {
            unsafe {
                hwexception_throw(
                    addr_of!(extinfo).cast(),
                    std::mem::size_of_val(&extinfo),
                    jmp_buf.get(),
                    err_buf.get(),
                )
            }
            false
        })
    })
}

/// Catches an exception raised by [`throw`].
///
/// Runs `block`. If an exception is thrown during its execution, returns boxed
/// exception details. Otherwise, returns the return value of the block.
///
/// Internally, this function sets up a `setjmp` buffer, and [`throw`] performs
/// a `longjmp` back to it. No unwinding occurs: drop methods for any objects
/// created in the dynamic scope of the callback will not run. So, be wary of
/// resource leaks.
///
/// Despite this function's similar type signature to
/// [`std::panic::catch_unwind`], exceptions and panics are distinct. This
/// function will not catch panics and `catch_unwind` will not catch exceptions.
/// If `block` panics, the panic will continue to propagate out from this call.
///
/// This function will not catch anything that was not thrown by [`throw`], so a
/// signal being raised during the execution of `block` will not automatically
/// result in it being caught. You first need to use [`register_hook`] to
/// register a hook which calls `throw`.
pub fn catch<F, R>(block: F) -> Result<R, ExtExceptionInfo>
where
    F: FnOnce() -> R + UnwindSafe,
{
    // Okay, so here our control flow is spaghetti embedded in five-dimensional
    // non-Euclidean space. We're going to be calling into the C function
    // hwexception_catch. hwexception_catch *has* to be written in C, because it
    // calls setjmp. setjmp returns twice, which is something Rust fundamentally
    // can't cope with. But hwexception_catch only returns once, so it's okay
    // for us to call into it from Rust code.
    //
    // hwexception_catch takes five arguments:
    // 1. A pointer to a (C ABI) callback function which accepts a void* context
    //    argument.
    // 2. A context argument to pass to the callback.
    // 3. A pointer to a buffer where `hwexcept_throw` can record exception
    //    info. Specifically, this buffer will be holding an ExtExceptionInfo.
    // 4. A pointer to thread-local storage which can be used to stash a pointer
    //    to a setjmp buffer.
    // 5. A pointer to thread-local storage which can be used to stash a copy of
    //    the pointer from argument 3.
    //
    // hwexception_catch is going to set up a jump buffer, store the two
    // pointers in the TLS cells we've given it, call the callback, restore the
    // TLS cells to their original values, and then return 0 if no exception was
    // thrown or nonzero otherwise. Whatever's stored in the TLS cells will be
    // looked up by our throw function.
    //
    // The job of this function is to wrap up the Rust-ABI closure `block` into
    // something callable from C. In addition to the obvious pointer-wrangling,
    // this also necessitates dealing with panics. Unwinding from a panic will
    // cause an immediate process abort if the unwind crosses a non-Rust frame,
    // and we don't want to happen. So, panics that come out of `block` need get
    // caught before they hit any C frame, and then rethrown once
    // `hwexcept_throw` has returned and we're safely back in Rust-land.


    // Before we call into hwexcept_throw, this union will hold `block` in its
    // `call` member. After hwexcept_throw returns, `call` (an FnOnce) will have
    // been consumed, and this union will be in one of three states:
    // 1. If the block returned normally, this union's `noexception` member will
    //    hold an Ok() of its return value.
    // 2. If the block panicked, this union's `noexception` member will hold an
    //    Err() of the panic payload.
    // 3. If the block raised an exception, this union will hold a Box<dyn
    //    Exception> in its `exception` member.
    // We'll be using a pointer to a result buffer as the context argument to
    // our callback.
    union ResultBuffer<F, R> {
        call: ManuallyDrop<F>,
        noexception: ManuallyDrop<Result<R, Box<dyn Any + Send>>>,
        exception: ManuallyDrop<ExtExceptionInfo>,
    }

    // This is the callback we'll passing as our first argument to hwexcept_throw.
    unsafe extern "C" fn callback<F, R>(ctx: *mut c_void)
    where
        F: FnOnce() -> R + UnwindSafe,
    {
        let ctx: &mut ResultBuffer<F, R> = &mut *ctx.cast();
        // Cast the void* context argument back into its real type.
        let f = ManuallyDrop::take(&mut ctx.call);
        // Call it, and if it panics, catch it.
        let result = std::panic::catch_unwind(f);
        // If we reach this line, no exception was raised. Write the result into
        // the `noexception` member of the ResultBuffer.
        ctx.noexception = ManuallyDrop::new(result);
    }

    // Create the result buffer in its initial state with its `call` member
    // active.
    let mut result_buffer = ResultBuffer::<F, R> {
        call: ManuallyDrop::new(block),
    };

    unsafe {
        JMP_BUF_PTR.with(|jmp_buf| {
            ERR_BUF_PTR.with(|err_buf| {
                if hwexception_catch(
                    callback::<F, R>,
                    addr_of_mut!(result_buffer).cast(),
                    addr_of_mut!(result_buffer.exception).cast(),
                    jmp_buf.get(),
                    err_buf.get(),
                ) == 0
                {
                    // A zero return means that no exception was raised, so we reached
                    // the end of the callback and now the `noexception` member contains
                    // what the callback stored into it, so extract it. If it's a normal
                    // return, return it. If it's a panic, resume panicking.
                    match ManuallyDrop::into_inner(result_buffer.noexception) {
                        Ok(success) => Ok(success),
                        Err(payload) => std::panic::resume_unwind(payload),
                    }
                } else {
                    // A non-zero return means that an exception was raised, and now the
                    // `exception` member contains what the throw function put there.
                    // Extract this and return it.
                    Err(ManuallyDrop::into_inner(result_buffer.exception))
                }
            })
        })
    }
}
