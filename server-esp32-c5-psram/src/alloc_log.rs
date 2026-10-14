//! Size-filtered logging global allocator with call stacks — for hunting big
//! allocations and where they come from.
//!
//! Wraps the platform [`System`] allocator. For every allocation/realloc at or
//! above [`THRESHOLD`] it prints `ptr + size` then a backtrace via
//! [`esp_backtrace_print`], which is allocation-free (it's what the panic
//! handler uses), so it can't recurse back into the allocator. Frees ≥
//! `THRESHOLD` are logged as `ptr + size` only — pair an alloc with its free by
//! pointer to tell *held* (persistent) chunks from transient ones.
//!
//! All output goes through `esp_rom_printf` (also allocation-free). A
//! re-entrancy guard is belt-and-suspenders (and avoids nested-log interleaving).
//!
//! Reading a backtrace: the first ~2-3 frames are the allocator itself
//! (`LoggingAlloc`, `System`, Rust shims); the real caller is just above. Decode
//! with `xtensa-esp32-elf-addr2line -e <elf> <pc> <pc> …` (use the
//! `xtensa-esp32s3-elf-addr2line` variant on the S3).
//!
//! [`esp_backtrace_print`]: esp_idf_svc::sys::esp_backtrace_print

use core::ffi::{c_int, c_uint};
use core::sync::atomic::{AtomicBool, Ordering};
use std::alloc::{GlobalAlloc, Layout, System};

/// Only log allocations/frees this size or larger.
const THRESHOLD: usize = 2048;

/// Backtrace depth (frames). The first few are the allocator; the rest is the
/// caller chain.
const BT_DEPTH: c_int = 12;

/// Re-entrancy / interleave guard for the logging path.
static IN_LOG: AtomicBool = AtomicBool::new(false);

pub struct LoggingAlloc;

#[inline]
fn log_alloc(tag: &core::ffi::CStr, ptr: *mut u8, size: usize) {
    // esp_rom_printf / esp_backtrace_print never allocate, so this cannot recurse
    // into alloc(); the guard is insurance and keeps a backtrace from being
    // interleaved with another core's log.
    if IN_LOG.swap(true, Ordering::Acquire) {
        return;
    }
    unsafe {
        esp_idf_svc::sys::esp_rom_printf(tag.as_ptr(), ptr as usize as c_uint, size as c_uint);
        let _ = esp_idf_svc::sys::esp_backtrace_print(BT_DEPTH);
    }
    IN_LOG.store(false, Ordering::Release);
}

#[inline]
fn log_free(ptr: *mut u8, size: usize) {
    // No backtrace, no guard: one allocation-free printf, so all frees are kept
    // (needed to pair against allocs by pointer).
    unsafe {
        esp_idf_svc::sys::esp_rom_printf(
            c"[free] p=%x s=%u\n".as_ptr(),
            ptr as usize as c_uint,
            size as c_uint,
        );
    }
}

unsafe impl GlobalAlloc for LoggingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() && layout.size() >= THRESHOLD {
            log_alloc(c"[alloc] p=%x s=%u\n", p, layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(layout);
        if !p.is_null() && layout.size() >= THRESHOLD {
            log_alloc(c"[alloc0] p=%x s=%u\n", p, layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() >= THRESHOLD {
            log_free(ptr, layout.size());
        }
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, layout, new_size);
        if !p.is_null() && new_size >= THRESHOLD {
            log_alloc(c"[realloc] p=%x s=%u\n", p, new_size);
        }
        p
    }
}
