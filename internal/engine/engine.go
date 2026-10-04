// Package engine calls the Rust inspection and policy engines through the
// kravyx-ffi C ABI (ADR-006). Build the static library first:
//
//	cargo build --release -p kravyx-ffi
package engine

/*
#cgo CFLAGS: -I${SRCDIR}/../../core/ffi/include
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -lkravyx_ffi -ldl -lpthread -lm
#include <stdlib.h>
#include "kravyx.h"
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
	"unsafe"
)

// Error is a structured engine error. Codes: invalid_input, invalid_bundle, too_large, internal.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
	Error  *Error          `json:"error"`
}

// take converts and frees a string returned by the FFI.
func take(p *C.char) (json.RawMessage, error) {
	if p == nil {
		return nil, &Error{Code: "internal", Message: "engine returned null"}
	}
	defer C.kx_free(p)
	var env envelope
	if err := json.Unmarshal([]byte(C.GoString(p)), &env); err != nil {
		return nil, &Error{Code: "internal", Message: fmt.Sprintf("bad engine output: %v", err)}
	}
	if !env.OK {
		if env.Error == nil {
			return nil, &Error{Code: "internal", Message: "engine failed without error"}
		}
		return nil, env.Error
	}
	return env.Result, nil
}

// cstr copies b into C memory. JSON containing a NUL byte is rejected (it would
// otherwise be silently truncated at the C boundary).
func cstr(b []byte) (*C.char, error) {
	if bytes.IndexByte(b, 0) >= 0 {
		return nil, &Error{Code: "invalid_input", Message: "input contains a NUL byte"}
	}
	return C.CString(string(b)), nil
}

// Info returns engine metadata (versions, detector ids).
func Info() (json.RawMessage, error) { return take(C.kx_engine_info()) }

// Validate compiles a policy bundle.
func Validate(bundle []byte) (json.RawMessage, error) {
	cb, err := cstr(bundle)
	if err != nil {
		return nil, err
	}
	defer C.free(unsafe.Pointer(cb))
	return take(C.kx_policy_validate(cb))
}

// Simulate inspects optional content and evaluates the bundle with a full trace.
// Content is passed by pointer for the duration of the call only; the engine
// does not retain it.
func Simulate(bundle, context, content []byte, at time.Time) (json.RawMessage, error) {
	cb, err := cstr(bundle)
	if err != nil {
		return nil, err
	}
	defer C.free(unsafe.Pointer(cb))
	cc, err := cstr(context)
	if err != nil {
		return nil, err
	}
	defer C.free(unsafe.Pointer(cc))
	var ptr *C.uint8_t
	if len(content) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&content[0]))
	}
	return take(C.kx_policy_simulate(cb, cc, ptr, C.size_t(len(content)), C.int64_t(at.Unix())))
}
