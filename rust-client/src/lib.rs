//! Morph Core Shared Library Crate (`libmorph_core.so` for Android JNI + reusable Rust core).
//! Preserves 100% of existing Windows/Linux binary behavior without modifying any core module.

#![deny(warnings)]

pub mod common;
pub mod core;
pub mod mimic;

#[cfg(target_os = "android")]
pub mod client {
    pub mod android_engine;
}

#[cfg(target_os = "android")]
pub mod android_jni;
