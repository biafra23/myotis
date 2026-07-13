//! The Rust implementation of the `io.myotis.api` engine contract, exposed to the
//! JVM via hand-JNI (compound records cross as JSON — see the phase-1 plan and
//! docs/reimplementation/05).
//!
//! R1 (this stage): the network CATALOG is answered from Rust (`nativeInit` ABI
//! handshake, `nativeAvailableNetworksJson`, `nativeCanonicalNetworkName`) AND the
//! engine can HOST mainnet — `nativeCreate`/`nativeStart`/`nativeStatusJson`/
//! `nativeStop` drive a `myotis_net::SyncHandle` (the light-client sync loop) on a
//! tokio runtime this crate owns (see `host`). R1 is CL-only + mainnet-only; Gnosis
//! and the EL surface land later.

pub mod catalog;
mod eljson;
mod host;
pub mod ringlog;

/// Bumped whenever the JNI surface changes shape. Checked by the Java wrapper's
/// availability probe (`nativeInit`) before any other native call — a stale .so
/// on the library path makes the Rust engine report "unavailable" instead of
/// crashing on a missing/renamed symbol.
///
/// v2: added the hosting surface (nativeCreate/Start/StatusJson/Stop).
/// v4: added the EL verified-read surface (nativeRequestAccountJson,
///     nativeGetStorageProofJson), wired into the Java RustEngineNative /
///     RustChainHandle at the same time so no .so ever reports an ABI the
///     running Java engine treats as stale.
/// v9: added nativeEthCallJson (eth_call over verified state via the revm executor).
/// v10: added nativeEstimateGasJson (eth_estimateGas over the revm executor).
/// v11: added nativeResolveEnsJson (ENS forward resolution over verified eth_calls).
/// v12: added nativeEnsRecordJson (all ENS record types + reverse + root modes,
///      one generic dispatch — EL-C-5-2).
/// v13: added the idle-sleep surface (nativePause/nativeResume) and the
///      `paused` key in the status JSON, wired into the Java RustEngineNative /
///      RustChainHandle at the same time.
pub const ABI_VERSION: i32 = 13;

// Keep the workspace edge alive so `cargo build -p myotis-engine` type-checks the
// consensus crate too.
pub use myotis_consensus::bls_dst;

mod jni_shim {
    use jni::objects::{JClass, JString};
    use jni::sys::{jboolean, jint, jlong, jstring, JNI_FALSE, JNI_TRUE};
    use jni::JNIEnv;

    /// Read a JString into a Rust String, or `None` for null / a JNI error.
    /// Panic-free (the workspace is `panic = "abort"`; a panic here aborts the
    /// JVM): every failure path returns None instead of unwrapping.
    fn read_string(env: &mut JNIEnv, s: &JString) -> Option<String> {
        if s.is_null() {
            return None;
        }
        env.get_string(s).ok().map(Into::into)
    }

    /// `RustEngineNative.nativeInit()` — the availability + ABI handshake.
    /// Also installs the global tracing subscriber feeding the drainable ring
    /// (idempotent), so every line the engine logs from here on is observable.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeInit(
        _env: JNIEnv,
        _class: JClass,
    ) -> jint {
        crate::ringlog::init();
        crate::ABI_VERSION
    }

    /// `RustEngineNative.nativeDrainLogs(int)` — up to `max` buffered tracing
    /// lines, oldest first, newline-joined; empty string when idle. Hosts pump
    /// this into their own log pipeline (Android LogBuffer → Logs tab/logcat).
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeDrainLogs(
        env: JNIEnv,
        _class: JClass,
        max: jint,
    ) -> jstring {
        let batch = crate::ringlog::drain(max.max(0) as usize);
        match env.new_string(batch) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
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

    // ---------------------------------------------------------------------
    // Hosting surface (ABI 2). Each native is panic-free by construction: the
    // workspace builds with `panic = "abort"`, so `catch_unwind` cannot catch a
    // panic here — a panic would abort the JVM. The `host` module functions
    // never unwrap/index on runtime state, and these shims only touch JNI values
    // through fallible `read_string` + sentinel returns.
    // ---------------------------------------------------------------------

    /// `RustEngineNative.nativeCreate(String network, String dataDir)` — allocate
    /// a not-yet-started handle id. Returns the id (≥ 1), or a negative sentinel:
    /// -1 (`CREATE_FAILED`) for an unknown name / runtime-init failure, -2
    /// (`UNSUPPORTED_NETWORK`) for a canonical-but-not-mainnet network. Any `< 0`
    /// is a failure the Java side turns into a named EngineException.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeCreate(
        mut env: JNIEnv,
        _class: JClass,
        network: JString,
        data_dir: JString,
    ) -> jlong {
        let Some(network) = read_string(&mut env, &network) else {
            return -1;
        };
        // dataDir is optional at the native layer (the CL-only R1 sync loop keeps
        // no on-disk state yet); a null/garbage value must not crash the JVM.
        let data_dir = read_string(&mut env, &data_dir).unwrap_or_default();
        crate::host::create(&network, &data_dir)
    }

    /// `RustEngineNative.nativeStart(long handle)` — start the sync loop. True on
    /// success; false for an unknown / already-running handle or a start error.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeStart(
        _env: JNIEnv,
        _class: JClass,
        handle: jlong,
    ) -> jboolean {
        if crate::host::start(handle) {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }

    /// `RustEngineNative.nativeStatusJson(long handle)` — one handle's status as a
    /// JSON object (see host::status_object), or `"{}"` for an unknown handle.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeStatusJson(
        env: JNIEnv,
        _class: JClass,
        handle: jlong,
    ) -> jstring {
        let json = crate::host::status_json(handle);
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            // OOM-class failure: null. The Java wrapper treats a null status as a
            // not-running handle rather than crashing.
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// `RustEngineNative.nativeStop(long handle)` — remove + shut down the sync
    /// loop. No-op for an unknown id.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeStop(
        _env: JNIEnv,
        _class: JClass,
        handle: jlong,
    ) {
        crate::host::stop(handle);
    }

    // ---------------------------------------------------------------------
    // Idle-sleep surface (ABI 13): the ChainHandle contract's pause/resume.
    // Both return true ONLY on an actual transition (Running→Paused resp.
    // Paused→Running); the Java wrapper layers the contract's idempotent
    // semantics and the sleep accounting on top.
    // ---------------------------------------------------------------------

    /// `RustEngineNative.nativePause(long handle)` — tear down networking, keep
    /// the handle as PAUSED (warm state persisted for the resume warm-start).
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativePause(
        _env: JNIEnv,
        _class: JClass,
        handle: jlong,
    ) -> jboolean {
        if crate::host::pause(handle) {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }

    /// `RustEngineNative.nativeResume(long handle)` — rebuild networking for a
    /// paused handle. False when the rebuild failed (the handle stays PAUSED,
    /// retryable) or the handle isn't paused.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeResume(
        _env: JNIEnv,
        _class: JClass,
        handle: jlong,
    ) -> jboolean {
        if crate::host::resume(handle) {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }

    // ---------------------------------------------------------------------
    // EL verified-read surface (ABI 4). Each returns a JSON string: the full
    // AccountProofResult / StorageProofResult shape on success (verification
    // failures carry a `failReason`), or `{"error": "..."}` for a transport /
    // not-running / bad-input failure the Java side raises as an EngineException.
    // ---------------------------------------------------------------------

    /// `RustEngineNative.nativeRequestAccountJson(long handle, String address)`.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeRequestAccountJson(
        mut env: JNIEnv,
        _class: JClass,
        handle: jlong,
        address: JString,
    ) -> jstring {
        let address = read_string(&mut env, &address).unwrap_or_default();
        let json = crate::host::request_account_json(handle, &address);
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// `RustEngineNative.nativeGetStorageProofJson(long handle, String address,
    /// long slot, String holderOrNull)`.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeGetStorageProofJson(
        mut env: JNIEnv,
        _class: JClass,
        handle: jlong,
        address: JString,
        slot: jlong,
        holder: JString,
    ) -> jstring {
        let address = read_string(&mut env, &address).unwrap_or_default();
        // A null/absent holder is the plain-slot lookup.
        let holder = read_string(&mut env, &holder);
        let json = crate::host::get_storage_proof_json(handle, &address, slot, holder.as_deref());
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// `RustEngineNative.nativeGetCodeJson(long handle, String address)`.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeGetCodeJson(
        mut env: JNIEnv,
        _class: JClass,
        handle: jlong,
        address: JString,
    ) -> jstring {
        let address = read_string(&mut env, &address).unwrap_or_default();
        let json = crate::host::get_code_json(handle, &address);
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// `RustEngineNative.nativeGetStorageAtJson(long handle, String address,
    /// String position)` — a RAW 32-byte storage position (`eth_getStorageAt`),
    /// distinct from the `(slot, holder)` ERC-20 mapping form above.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeGetStorageAtJson(
        mut env: JNIEnv,
        _class: JClass,
        handle: jlong,
        address: JString,
        position: JString,
    ) -> jstring {
        let address = read_string(&mut env, &address).unwrap_or_default();
        let position = read_string(&mut env, &position).unwrap_or_default();
        let json = crate::host::get_storage_at_json(handle, &address, &position);
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// `RustEngineNative.nativeEthCallJson(long handle, String from, String to,
    /// String data, String valueDecimal, String block)` — verified `eth_call` over
    /// the revm executor. `from` empty ⇒ anonymous sender; `valueDecimal` is wei as
    /// a decimal string.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeEthCallJson(
        mut env: JNIEnv,
        _class: JClass,
        handle: jlong,
        from: JString,
        to: JString,
        data: JString,
        value: JString,
        block: JString,
    ) -> jstring {
        let from = read_string(&mut env, &from).unwrap_or_default();
        let to = read_string(&mut env, &to).unwrap_or_default();
        let data = read_string(&mut env, &data).unwrap_or_default();
        let value = read_string(&mut env, &value).unwrap_or_default();
        let block = read_string(&mut env, &block).unwrap_or_default();
        let json = crate::host::eth_call_json(handle, &from, &to, &data, &value, &block);
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// `RustEngineNative.nativeEstimateGasJson(long handle, String from, String to,
    /// String data, String valueDecimal)` — verified `eth_estimateGas` over the revm
    /// executor (runs against the verified head; no block arg). `from` empty ⇒
    /// anonymous sender; `valueDecimal` is wei as a decimal string.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeEstimateGasJson(
        mut env: JNIEnv,
        _class: JClass,
        handle: jlong,
        from: JString,
        to: JString,
        data: JString,
        value: JString,
    ) -> jstring {
        let from = read_string(&mut env, &from).unwrap_or_default();
        let to = read_string(&mut env, &to).unwrap_or_default();
        let data = read_string(&mut env, &data).unwrap_or_default();
        let value = read_string(&mut env, &value).unwrap_or_default();
        let json = crate::host::estimate_gas_json(handle, &from, &to, &data, &value);
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// `RustEngineNative.nativeResolveEnsJson(long handle, String name)` — verified
    /// ENS forward resolution (name → address record) over the revm executor.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeResolveEnsJson(
        mut env: JNIEnv,
        _class: JClass,
        handle: jlong,
        name: JString,
    ) -> jstring {
        let name = read_string(&mut env, &name).unwrap_or_default();
        let json = crate::host::resolve_ens_json(handle, &name);
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// `RustEngineNative.nativeEnsRecordJson(long handle, String paramsJson)` —
    /// one generic dispatch for every ENS record query (text, contenthash,
    /// multi-coin, pubkey, ABI, dnsRecord, interfaceImplementer, reverse, and
    /// root-aware addr). The method + args travel in `paramsJson`.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeEnsRecordJson(
        mut env: JNIEnv,
        _class: JClass,
        handle: jlong,
        params_json: JString,
    ) -> jstring {
        let params = read_string(&mut env, &params_json).unwrap_or_default();
        let json = crate::host::ens_record_json(handle, &params);
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// `RustEngineNative.nativeGetBlockByNumberJson(long handle, String blockTag)`
    /// — verified `eth_getBlockByNumber` (transactions as hashes). Returns the block
    /// JSON, the literal `"null"`, or `{"error": "..."}`.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeGetBlockByNumberJson(
        mut env: JNIEnv,
        _class: JClass,
        handle: jlong,
        block_tag: JString,
    ) -> jstring {
        let block_tag = read_string(&mut env, &block_tag).unwrap_or_default();
        let json = crate::host::get_block_by_number_json(handle, &block_tag);
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// `RustEngineNative.nativeFeeEstimateJson(long handle)` — verified
    /// `eth_gasPrice` + `eth_maxPriorityFeePerGas`. Returns
    /// `{"gasPriceWei","maxPriorityFeePerGasWei"}` or `{"error": "..."}`.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeFeeEstimateJson(
        env: JNIEnv,
        _class: JClass,
        handle: jlong,
    ) -> jstring {
        let json = crate::host::fee_estimate_json(handle);
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// `RustEngineNative.nativeSendRawTransactionJson(long handle, String rawTxHex)`
    /// — gossip a signed raw tx. Returns `{"txHash":"0x…"}` or `{"error": "..."}`.
    #[no_mangle]
    pub extern "system" fn Java_io_myotis_engines_RustEngineNative_nativeSendRawTransactionJson(
        mut env: JNIEnv,
        _class: JClass,
        handle: jlong,
        raw_tx_hex: JString,
    ) -> jstring {
        let raw_tx_hex = read_string(&mut env, &raw_tx_hex).unwrap_or_default();
        let json = crate::host::send_raw_transaction_json(handle, &raw_tx_hex);
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }
}
