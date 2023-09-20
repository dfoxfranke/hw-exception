// Copyright (c) 2023 Daniel Fox Franke
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

// This file is currently unused. It declares all the bits of POSIX that this
// crate needs in order to compile, so that we can do a trial compilation and
// give a helpful error message. Unfortunately, convincing cargo to do this test
// properly turned out to be more trouble than it's worth, so instead build.rs
// just checks that CARGO_CFG_TARGET_FAMILY is "unix".

extern crate libc;

const SIGILL : () = (libc::SIGILL, ()).1;
const SIGFPE : () = (libc::SIGFPE, ()).1;
const SIGSEGV : () = (libc::SIGSEGV, ()).1;
const SIGBUS : () = (libc::SIGBUS, ()).1;
const SIGTRAP : () = (libc::SIGTRAP, ()).1;
const SIG_DFL : () = (libc::SIG_DFL, ()).1;
const SIG_IGN : () = (libc::SIG_IGN, ()).1;
const SIG_ERR : () = (libc::SIG_ERR, ()).1;
const SA_NODEFER : () = (libc::SA_NODEFER, ()).1;
const SA_ONSTACK : () = (libc::SA_ONSTACK, ()).1;
const SA_SIGINFO : () = (libc::SA_SIGINFO, ()).1;

type sigaction = libc::sigaction;
type siginfo_t = libc::siginfo_t;
type sigset_t = libc::sigset_t;

fn main() {
    let _ = libc::sigaction;
    let _ = libc::signal;
}