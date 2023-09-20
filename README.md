# `hw-exception`

This Rust crate handles POSIX signals which are triggered in response to
hardware exceptions. These signals include:

* `SIGILL`
* `SIGFPE`
* `SIGSEGV`
* `SIGBUS`
* `SIGTRAP`

Examples of hardware exceptions which trigger them include:

* Illegal instructions
* General protection faults
* Divide-by-zero errors
* Floating point exceptions
* Page faults
* General protection faults
* Machine check exceptions (raised, *e.g.*, on double-bit errors from ECC memory)
* Hardware breakpoints

Normally, receiving any of these signals indicates either a hardware failure
or certain kinds of bugs which shouldn't be possible in safe Rust code. When
they're received unexpectedly, the only sensible way to proceed is to abort
the process and dump core, which is exactly what would normally happen.
However, many use cases exist where such signals are expected, and recovery
is possible. Here are just a few:

* **Stop-and-copy garbage collectors**. Certain garbage-collection
  techniques routinely trigger segmentation faults. The signal handler can
  map a valid page into the faulting address and then execution can resume
  where it left off. (Consider the
  [`userfaultfd`](https://docs.rs/userfaultfd) crate as an alternative for
  this and similar use cases.)
* **Sharing memory with untrusted peers**. Writers to a shared memory
  segment can do various unfriendly things, such as truncating it
  unexpectedly, which will cause other processes accessing the segment to
  get a `SIGBUS`, which they can't guard against without running into TOCTOU
  problems. Victims of such behavior can catch the signal and jump back to a
  recovery point. (Consider the [`memfd`](https://docs.rs/memfd) crate as an
  alternative to avoid such complications.)
* **Fancy numerical stuff**. Sometimes it's more efficient to let a
  divide-by-zero or a floating point exception occur than it is to check
  every operation which might trigger it.
* **Robust storage layers**. As the size of disk or memory approaches
  infinity, the probability of a hardware error approaches one. Catching
  machine check exceptions makes it possible to handle such failures
  robustly by switching to redundant storage or by tolerating small amounts
  of data loss.
* **Debuggers**, which will get a `SIGTRAP` upon hitting a breakpoint
  they've set.

Hardware exceptions are generally handled in one of three ways; this crate
supports all of them to varying degrees. They are:

* **Patch and continue**: Fix the problem from within the signal handler,
  and then return from it to re-execute the excepting instruction. For
  example, by mapping a valid page to correct a segmentation fault.
* **Catch and recover**: Use `setjmp` to store a recovery point, and then
  `longjmp` back to it from the signal handler.
* **Scream and die**: Don't attempt to recover from the exception at all;
  just use the signal handler to log some diagnostics before aborting.

## Example

The following example triggers a segmentation fault by dereferencing a null
pointer, catches and recovers from it, and then prints a backtrace showing where
the segfault occurred.

```rust
use hw_exception::*;
use std::backtrace::Backtrace;

fn main() {
  unsafe {
    // Register a hook for SIGSEGV, which captures and throws a backtrace.
    register_hook(&[Signo::SIGSEGV], |e| {
      let bt = Backtrace::force_capture();
      throw((e, bt))
    });
  }
 
  // Dereference a null pointer from within a `catch` block. Using `read_volatile`
  // prevents this from being UB.
  let result = catch(|| unsafe {
     std::ptr::null::<usize>().read_volatile()
  });
 
  // Assert that this block resulted in an exception, and extract it.
  let e = result.expect_err("dereferencing a null pointer should have segfaulted, but gave");
 
  // Extract and print the backtrace
  let bt : &Backtrace = e
     .additional()
     .expect("thrown exception info should have included additional data")
     .downcast_ref()
     .expect("additional data should have been a `Backtrace`");
  println!("{}", bt);
}
```

## Documentation

See [API docs on docs.rs](https://docs.rs/hw-exception).

## License

This project licensed under the [Apache License
2.0](https://spdx.org/licenses/Apache-2.0.html) with [LLVM
exception](https://spdx.org/licenses/LLVM-exception.html). Unless you explicitly
state otherwise, any contribution intentionally submitted for inclusion in
`hw-exception` by you, shall be licensed as Apache 2.0 with LLVM exception,
without any additional terms or conditions.