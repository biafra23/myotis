//! The Rust implementation of the `io.myotis.api` engine contract, exposed to the
//! JVM via hand-JNI (compound records cross as JSON — see the phase-1 plan and
//! docs/reimplementation/05).
//!
//! R0 (this stage): the network CATALOG is answered from Rust — `nativeInit` (ABI
//! handshake), `nativeAvailableNetworksJson`, `nativeCanonicalNetworkName`. Hosting
//! (`create`/`start`) stays Java-side until the consensus crate lands (PR 4-6);
//! `RustMyotisEngine.create()` fails with a named error until then.

pub mod catalog;

/// Bumped whenever the JNI surface changes shape. Checked by the Java wrapper's
/// availability probe (`nativeInit`) before any other native call — a stale .so
/// on the library path makes the Rust engine report "unavailable" instead of
/// crashing on a missing/renamed symbol.
pub const ABI_VERSION: i32 = 1;

// Keep the workspace edge alive so `cargo build -p myotis-engine` type-checks the
// consensus crate too.
pub use myotis_consensus::bls_dst;

mod jni_shim {
    use jni::objects::{JClass, JString};
    use jni::sys::{jint, jstring};
    use jni::JNIEnv;

    /// `RustEngineNative.nativeInit()` — the availability + ABI handshake.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeInit(
        _env: JNIEnv,
        _class: JClass,
    ) -> jint {
        crate::ABI_VERSION
    }

    /// `RustEngineNative.nativeAvailableNetworksJson()` — the embedded catalog as a
    /// JSON array of `NetworkInfo` objects (camelCase keys, display order).
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeAvailableNetworksJson(
        env: JNIEnv,
        _class: JClass,
    ) -> jstring {
        match env.new_string(crate::catalog::networks_json()) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(), // OOM-class failure; Java treats null as unavailable
        }
    }

    /// `RustEngineNative.nativeCanonicalNetworkName(String)` — canonical name, or
    /// null for an unknown network (the Java wrapper raises `EngineException`).
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeCanonicalNetworkName(
        mut env: JNIEnv,
        _class: JClass,
        name_or_alias: JString,
    ) -> jstring {
        // Defensive null check BEFORE get_string: JNI string functions don't accept
        // null references (undefined behavior — can segfault the JVM, not throw). The
        // Java wrapper null-checks too, but the native side must not rely on that.
        if name_or_alias.is_null() {
            return std::ptr::null_mut();
        }
        let input: String = match env.get_string(&name_or_alias) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };
        match crate::catalog::canonical_network_name(&input) {
            Some(canonical) => match env.new_string(canonical) {
                Ok(s) => s.into_raw(),
                Err(_) => std::ptr::null_mut(),
            },
            None => std::ptr::null_mut(),
        }
    }
}
