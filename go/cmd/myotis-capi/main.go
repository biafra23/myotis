// Command myotis-capi is the Go engine as a c-shared library: the C ABI
// of rust/include/myotis_engine.h (ABI 57), implemented over
// internal/capi for JVM JNA consumers (desktop-embed step 1, part 1b).
//
// Every symbol the header declares is exported — functional for the
// read-engine subset, an honest refusal for the rest — so a host
// binding written against the Rust engine loads this library by name
// alone. internal/capi's package doc states the full contract and
// where each function sits on the functional/refused line;
// myotis_go_capabilities_json (a Go-only export) answers it at
// runtime. Build:
//
//	go build -buildmode=c-shared -o build/libmyotis_engine_go.so ./cmd/myotis-capi
//
// Every char* returned is a C.CString the CALLER frees with
// myotis_string_free — the header's ownership rule, mirrored exactly.
package main

/*
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
// The CONTRACT itself, compiled in: cgo re-declares every //export
// next to this preamble, so a signature that drifts from the header
// becomes a C "conflicting types" BUILD error, not a silent ABI lie
// the name-only symbol check would wave through (PR #827 review —
// four stubs had drifted prototypes that way). The include path is
// relative to this package dir, matching what the go-engine workflow
// builds with (working-directory go/).
#include "../../../rust/include/myotis_engine.h"
// const char* under a name cgo can name as a parameter type.
typedef const char cchar_t;
*/
import "C"

import (
	"unsafe"

	"github.com/biafra23/myotis/go/internal/capi"
)

func main() {} // c-shared entry point; never runs

// cstr copies a Go string into malloc'd C memory for the caller to
// free via myotis_string_free (the header's ownership contract).
func cstr(s string) *C.char { return C.CString(s) }

// gostrC reads a possibly-NULL C string — the header's char*
// parameters are all const char*, which the preamble's typedef makes
// *C.cchar_t for cgo — as a Go string.
func gostrC(p *C.cchar_t) string {
	if p == nil {
		return ""
	}
	return C.GoString((*C.char)(unsafe.Pointer(p)))
}

// ---- availability + handshake ----

//export myotis_init
func myotis_init() C.int32_t { return C.int32_t(capi.Init()) }

//export myotis_drain_logs
func myotis_drain_logs(max C.int32_t) *C.char { return cstr(capi.DrainLogs(int(max))) }

//export myotis_available_networks_json
func myotis_available_networks_json() *C.char { return cstr(capi.AvailableNetworksJSON()) }

//export myotis_canonical_network_name
func myotis_canonical_network_name(name *C.cchar_t) *C.char {
	c, ok := capi.CanonicalNetworkName(gostrC(name))
	if !ok {
		return nil // NULL for unknown, per the header
	}
	return cstr(c)
}

// Go-only export (not in the header): the functional/refused split.
//
//export myotis_go_capabilities_json
func myotis_go_capabilities_json() *C.char { return cstr(capi.CapabilitiesJSON()) }

// ---- lifecycle ----

//export myotis_create
func myotis_create(network, dataDir *C.cchar_t) C.int64_t {
	return C.int64_t(capi.Create(gostrC(network), gostrC(dataDir)))
}

//export myotis_create_with_checkpoint
func myotis_create_with_checkpoint(network, dataDir, root *C.cchar_t, slot C.uint64_t) C.int64_t {
	_ = slot
	return C.int64_t(capi.CreateWithCheckpoint(gostrC(network), gostrC(dataDir), gostrC(root)))
}

//export myotis_start
func myotis_start(handle C.int64_t) C.bool { return C.bool(capi.Start(int64(handle))) }

//export myotis_stop
func myotis_stop(handle C.int64_t) { capi.Stop(int64(handle)) }

//export myotis_status_json
func myotis_status_json(handle C.int64_t) *C.char { return cstr(capi.StatusJSON(int64(handle))) }

//export myotis_pause
func myotis_pause(handle C.int64_t) C.bool { return C.bool(capi.Pause(int64(handle))) }

//export myotis_resume
func myotis_resume(handle C.int64_t) C.bool { return C.bool(capi.Resume(int64(handle))) }

// ---- process-global toggles ----

//export myotis_set_tor_enabled
func myotis_set_tor_enabled(on C.bool) C.bool { return C.bool(capi.SetTorEnabled(bool(on))) }

//export myotis_tor_status
func myotis_tor_status() C.int32_t { return C.int32_t(capi.TorStatus()) } // 0 = no Tor support in this build

//export myotis_set_tor_storage_dirs
func myotis_set_tor_storage_dirs(stateDir, cacheDir *C.cchar_t) C.bool {
	return C.bool(capi.SetTorStorageDirs(gostrC(stateDir), gostrC(cacheDir)))
}

//export myotis_set_dns_discovery
func myotis_set_dns_discovery(on C.bool) C.bool { return C.bool(capi.SetDNSDiscovery(bool(on))) }

//export myotis_set_network_metering
func myotis_set_network_metering(code C.int32_t) C.bool {
	return C.bool(capi.SetNetworkMetering(int32(code)))
}

//export myotis_network_metering
func myotis_network_metering() C.int32_t { return C.int32_t(capi.NetworkMetering()) }

// ---- verified reads ----

//export myotis_request_account_json
func myotis_request_account_json(handle C.int64_t, address, block *C.cchar_t) *C.char {
	return cstr(capi.RequestAccountJSON(int64(handle), gostrC(address), gostrC(block)))
}

//export myotis_get_storage_proof_json
func myotis_get_storage_proof_json(handle C.int64_t, address *C.cchar_t, slot C.int64_t, holder *C.cchar_t) *C.char {
	return cstr(capi.GetStorageProofJSON(int64(handle), gostrC(address), int64(slot), gostrC(holder)))
}

// ---- memory ----

//export myotis_string_free
func myotis_string_free(s *C.char) { C.free(unsafe.Pointer(s)) }

// ---- refused exports (functional in the Rust engine, not in this
// read-only one): JSON getters answer the permanent -32602 refusal,
// setters answer false, so a host sees the capability line at the
// exact call site. Each name is the refusal message. ----

//export myotis_get_code_json
func myotis_get_code_json(h C.int64_t, a, b *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_get_code_json"))
}

//export myotis_get_storage_at_json
func myotis_get_storage_at_json(h C.int64_t, a, p, b *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_get_storage_at_json"))
}

//export myotis_get_proof_json
func myotis_get_proof_json(h C.int64_t, a, k, b *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_get_proof_json"))
}

//export myotis_eth_call_json
func myotis_eth_call_json(h C.int64_t, f, t, d, v, b *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_eth_call_json"))
}

//export myotis_eth_call_overrides_json
func myotis_eth_call_overrides_json(h C.int64_t, f, t, d, v, b, o *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_eth_call_overrides_json"))
}

//export myotis_eth_call_tx_json
func myotis_eth_call_tx_json(h C.int64_t, tx, b, o *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_eth_call_tx_json"))
}

//export myotis_estimate_gas_json
func myotis_estimate_gas_json(h C.int64_t, f, t, d, v *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_estimate_gas_json"))
}

//export myotis_estimate_gas_tx_json
func myotis_estimate_gas_tx_json(h C.int64_t, tx, b, o *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_estimate_gas_tx_json"))
}

//export myotis_create_access_list_json
func myotis_create_access_list_json(h C.int64_t, tx, b, o *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_create_access_list_json"))
}

//export myotis_resolve_ens_json
func myotis_resolve_ens_json(h C.int64_t, name *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_resolve_ens_json"))
}

//export myotis_ens_record_json
func myotis_ens_record_json(h C.int64_t, params *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_ens_record_json"))
}

//export myotis_get_block_by_number_json
func myotis_get_block_by_number_json(h C.int64_t, tag *C.cchar_t, full C.bool) *C.char {
	return cstr(capi.Unsupported("myotis_get_block_by_number_json"))
}

//export myotis_get_block_by_hash_json
func myotis_get_block_by_hash_json(h C.int64_t, hash *C.cchar_t, full C.bool) *C.char {
	return cstr(capi.Unsupported("myotis_get_block_by_hash_json"))
}

//export myotis_get_block_receipts_json
func myotis_get_block_receipts_json(h C.int64_t, sel *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_get_block_receipts_json"))
}

//export myotis_pending_nonce_overlay
func myotis_pending_nonce_overlay(h C.int64_t, a *C.cchar_t, mined C.int64_t) C.int64_t {
	return C.int64_t(capi.PendingNonceOverlay(int64(h), gostrC(a), int64(mined)))
}

//export myotis_get_transaction_receipt_json
func myotis_get_transaction_receipt_json(h C.int64_t, hash *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_get_transaction_receipt_json"))
}

//export myotis_get_transaction_by_hash_json
func myotis_get_transaction_by_hash_json(h C.int64_t, hash *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_get_transaction_by_hash_json"))
}

//export myotis_resolve_block_hash_json
func myotis_resolve_block_hash_json(h C.int64_t, sel *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_resolve_block_hash_json"))
}

//export myotis_debug_trace_call_json
func myotis_debug_trace_call_json(h C.int64_t, tx, b, ov, tr *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_debug_trace_call_json"))
}

//export myotis_simulate_v1_json
func myotis_simulate_v1_json(h C.int64_t, opts, ctx *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_simulate_v1_json"))
}

//export myotis_get_raw_transaction_by_hash_json
func myotis_get_raw_transaction_by_hash_json(h C.int64_t, hash *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_get_raw_transaction_by_hash_json"))
}

//export myotis_get_raw_transaction_by_block_json
func myotis_get_raw_transaction_by_block_json(h C.int64_t, sel *C.cchar_t, idx C.uint64_t) *C.char {
	return cstr(capi.Unsupported("myotis_get_raw_transaction_by_block_json"))
}

//export myotis_fee_estimate_json
func myotis_fee_estimate_json(h C.int64_t) *C.char {
	return cstr(capi.Unsupported("myotis_fee_estimate_json"))
}

//export myotis_fee_history_json
func myotis_fee_history_json(h C.int64_t, count C.int64_t, newest, percentiles *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_fee_history_json"))
}

//export myotis_send_raw_transaction_json
func myotis_send_raw_transaction_json(h C.int64_t, raw *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_send_raw_transaction_json"))
}

//export myotis_check_raw_transaction_json
func myotis_check_raw_transaction_json(raw *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_check_raw_transaction_json"))
}

//export myotis_get_logs_json
func myotis_get_logs_json(h C.int64_t, filter *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_get_logs_json"))
}

//export myotis_set_log_index_config
func myotis_set_log_index_config(h C.int64_t, cfg *C.cchar_t) C.bool { return C.bool(false) }

//export myotis_log_index_status_json
func myotis_log_index_status_json(h C.int64_t) *C.char {
	return cstr(capi.Unsupported("myotis_log_index_status_json"))
}

//export myotis_set_activity_watch
func myotis_set_activity_watch(h C.int64_t, cfg *C.cchar_t) C.bool { return C.bool(false) }

//export myotis_address_activity_json
func myotis_address_activity_json(h C.int64_t, after C.int64_t) *C.char {
	return cstr(capi.Unsupported("myotis_address_activity_json"))
}

//export myotis_read_stats_json
func myotis_read_stats_json(h C.int64_t) *C.char {
	return cstr(capi.Unsupported("myotis_read_stats_json"))
}

//export myotis_import_log_index_files
func myotis_import_log_index_files(h C.int64_t, paths *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_import_log_index_files"))
}

//export myotis_export_log_index
func myotis_export_log_index(h C.int64_t, path *C.cchar_t) *C.char {
	return cstr(capi.Unsupported("myotis_export_log_index"))
}

//export myotis_set_boot_enodes
func myotis_set_boot_enodes(h C.int64_t, enodes *C.cchar_t) C.bool { return C.bool(false) }

//export myotis_set_served_block_window
func myotis_set_served_block_window(h C.int64_t, blocks C.int32_t) C.bool {
	return C.bool(capi.SetServedBlockWindow(int64(h), int32(blocks)))
}

//export myotis_set_ws_bound_periods
func myotis_set_ws_bound_periods(h C.int64_t, periods C.int64_t) C.bool {
	return C.bool(capi.SetWsBoundPeriods(int64(h), int64(periods)))
}

//export myotis_accept_stale_anchor
func myotis_accept_stale_anchor(h C.int64_t) C.bool {
	return C.bool(capi.AcceptStaleAnchor(int64(h)))
}

//export myotis_set_listen_ports
func myotis_set_listen_ports(h C.int64_t, d4, d5, tcp, quic C.uint16_t) C.bool { return C.bool(false) }

var _ = unsafe.Pointer(nil)
