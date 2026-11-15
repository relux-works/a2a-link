package vaultv1

import "unicode/utf8"

// ValueKind enumerates the only admitted native types (CONTRACT-r4 section 5):
// dictionaries, strings, unsigned 64-bit integers, booleans, byte buffers,
// arrays and explicit null.
type ValueKind uint8

const (
	KindInvalid ValueKind = iota // zero Value; never admitted
	KindNull
	KindBool
	KindUint
	KindString
	KindBytes
	KindArray
	KindDict
)

// Value is the LOGICAL native value exchanged with the Driver. It is type
// notation, not a byte encoding: the qualified native driver owns the actual
// serialization, framing and its enforced byte cap. A dictionary keeps its
// fields in order so duplicate keys stay observable.
type Value struct {
	kind   ValueKind
	b      bool
	u      uint64
	s      string
	bytes  []byte
	items  []Value
	fields []Field
}

// Field is one dictionary entry.
type Field struct {
	Key   string
	Value Value
}

func Null() Value               { return Value{kind: KindNull} }
func Bool(b bool) Value         { return Value{kind: KindBool, b: b} }
func Uint(u uint64) Value       { return Value{kind: KindUint, u: u} }
func String(s string) Value     { return Value{kind: KindString, s: s} }
func Array(v ...Value) Value    { return Value{kind: KindArray, items: v} }
func Dict(f ...Field) Value     { return Value{kind: KindDict, fields: f} }
func F(k string, v Value) Field { return Field{Key: k, Value: v} }

// Bytes wraps b without copying. The receiver of a reply owns its buffers and
// this package clears them when it is done (success, refusal or UNKNOWN).
func Bytes(b []byte) Value { return Value{kind: KindBytes, bytes: b} }

func (v Value) Kind() ValueKind     { return v.kind }
func (v Value) BoolValue() bool     { return v.b }
func (v Value) UintValue() uint64   { return v.u }
func (v Value) StringValue() string { return v.s }
func (v Value) BytesValue() []byte  { return v.bytes }
func (v Value) Items() []Value      { return v.items }
func (v Value) Fields() []Field     { return v.fields }

const (
	maxDepth      = 8
	maxDictFields = 32
)

// admitted checks the type-level bounds that are independent of the byte
// encoding: nesting depth (top level is 1, at most 8), dictionary field count,
// unique keys and UTF-8 strings without NUL. Serialized-size accounting
// belongs to the driver.
func (v Value) admitted(depth int) (ok bool, overLimit bool) {
	if depth > maxDepth {
		return false, true
	}
	switch v.kind {
	case KindNull, KindBool, KindUint, KindBytes:
		return true, false
	case KindString:
		return validNativeString(v.s), false
	case KindArray:
		for _, it := range v.items {
			if ok, lim := it.admitted(depth + 1); !ok {
				return false, lim
			}
		}
		return true, false
	case KindDict:
		if len(v.fields) > maxDictFields {
			return false, true
		}
		seen := make(map[string]bool, len(v.fields))
		for _, f := range v.fields {
			if !validNativeString(f.Key) || seen[f.Key] {
				return false, false
			}
			seen[f.Key] = true
			if ok, lim := f.Value.admitted(depth + 1); !ok {
				return false, lim
			}
		}
		return true, false
	}
	return false, false
}

func validNativeString(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return false
		}
	}
	return true
}

// wipe clears every byte buffer reachable from v. It is best effort for the
// buffers this package owns; it is not a claim about driver, kernel or Go
// runtime copies.
func (v Value) wipe() {
	clear(v.bytes)
	for _, it := range v.items {
		it.wipe()
	}
	for _, f := range v.fields {
		f.Value.wipe()
	}
}

// closed returns the dictionary's fields by key when its key set is exactly
// keys. Any other shape, a missing key or an extra key returns ok=false.
func (v Value) closed(keys ...string) (map[string]Value, bool) {
	if v.kind != KindDict || len(v.fields) != len(keys) {
		return nil, false
	}
	out := make(map[string]Value, len(keys))
	for _, f := range v.fields {
		out[f.Key] = f.Value
	}
	for _, k := range keys {
		if _, ok := out[k]; !ok {
			return nil, false
		}
	}
	return out, len(out) == len(keys)
}
