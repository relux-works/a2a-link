package cli

import "unicode/utf8"

// vaultValueKind enumerates the only admitted native types (CONTRACT-r4 section 5):
// dictionaries, strings, unsigned 64-bit integers, booleans, byte buffers,
// arrays and explicit null.
type vaultValueKind uint8

const (
	vaultKindInvalid vaultValueKind = iota // zero vaultValue; never admitted
	vaultKindNull
	vaultKindBool
	vaultKindUint
	vaultKindString
	vaultKindBytes
	vaultKindArray
	vaultKindDict
)

// vaultValue is the LOGICAL native value exchanged with the vaultDriver. It is type
// notation, not a byte encoding: the qualified native driver owns the actual
// serialization, framing and its enforced byte cap. A dictionary keeps its
// fields in order so duplicate keys stay observable.
type vaultValue struct {
	kind   vaultValueKind
	b      bool
	u      uint64
	s      string
	bytes  []byte
	items  []vaultValue
	fields []vaultField
}

// vaultField is one dictionary entry.
type vaultField struct {
	Key        string
	vaultValue vaultValue
}

func vaultNull() vaultValue           { return vaultValue{kind: vaultKindNull} }
func vaultBool(b bool) vaultValue     { return vaultValue{kind: vaultKindBool, b: b} }
func vaultUint(u uint64) vaultValue   { return vaultValue{kind: vaultKindUint, u: u} }
func vaultString(s string) vaultValue { return vaultValue{kind: vaultKindString, s: s} }
func vaultArray(v ...vaultValue) vaultValue {
	return vaultValue{kind: vaultKindArray, items: vaultCloneValues(v)}
}
func vaultDict(f ...vaultField) vaultValue {
	return vaultValue{kind: vaultKindDict, fields: vaultCloneFields(f)}
}
func vaultF(k string, v vaultValue) vaultField { return vaultField{Key: k, vaultValue: v} }

// vaultBytes copies the caller bytes. Every retained value owns its buffers and
// this package clears them when it is done (success, failure or UNKNOWN).
func vaultBytes(b []byte) vaultValue {
	return vaultValue{kind: vaultKindBytes, bytes: append([]byte(nil), b...)}
}

func (v vaultValue) Kind() vaultValueKind { return v.kind }
func (v vaultValue) BoolValue() bool      { return v.b }
func (v vaultValue) UintValue() uint64    { return v.u }
func (v vaultValue) StringValue() string  { return v.s }
func (v vaultValue) BytesValue() []byte   { return append([]byte(nil), v.bytes...) }
func (v vaultValue) Items() []vaultValue  { return vaultCloneValues(v.items) }
func (v vaultValue) Fields() []vaultField { return vaultCloneFields(v.fields) }

const (
	vaultMaxDepth      = 8
	vaultMaxDictFields = 32
)

// admitted checks the type-level bounds that are independent of the byte
// encoding: nesting depth (top level is 1, at most 8), dictionary field count,
// unique keys and UTF-8 strings without NUL. Serialized-size accounting
// belongs to the driver.
func (v vaultValue) admitted(depth int) (ok bool, overLimit bool) {
	if depth > vaultMaxDepth {
		return false, true
	}
	switch v.kind {
	case vaultKindNull, vaultKindBool, vaultKindUint, vaultKindBytes:
		return true, false
	case vaultKindString:
		return vaultValidNativeString(v.s), false
	case vaultKindArray:
		for _, it := range v.items {
			if ok, lim := it.admitted(depth + 1); !ok {
				return false, lim
			}
		}
		return true, false
	case vaultKindDict:
		if len(v.fields) > vaultMaxDictFields {
			return false, true
		}
		seen := make(map[string]bool, len(v.fields))
		for _, f := range v.fields {
			if !vaultValidNativeString(f.Key) || seen[f.Key] {
				return false, false
			}
			seen[f.Key] = true
			if ok, lim := f.vaultValue.admitted(depth + 1); !ok {
				return false, lim
			}
		}
		return true, false
	}
	return false, false
}

func vaultValidNativeString(s string) bool {
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
func (v vaultValue) wipe() {
	clear(v.bytes)
	for _, it := range v.items {
		it.wipe()
	}
	for _, f := range v.fields {
		f.vaultValue.wipe()
	}
}

// closed returns the dictionary's fields by key when its key set is exactly
// keys. Any other shape, a missing key or an extra key returns ok=false.
func (v vaultValue) closed(keys ...string) (map[string]vaultValue, bool) {
	if v.kind != vaultKindDict || len(v.fields) != len(keys) {
		return nil, false
	}
	out := make(map[string]vaultValue, len(keys))
	for _, f := range v.fields {
		out[f.Key] = f.vaultValue
	}
	for _, k := range keys {
		if _, ok := out[k]; !ok {
			return nil, false
		}
	}
	return out, len(out) == len(keys)
}

func vaultCloneValues(v []vaultValue) []vaultValue {
	out := make([]vaultValue, len(v))
	for i := range v {
		out[i] = v[i].clone()
	}
	return out
}
func vaultCloneFields(v []vaultField) []vaultField {
	out := make([]vaultField, len(v))
	for i := range v {
		out[i] = vaultField{Key: v[i].Key, vaultValue: v[i].vaultValue.clone()}
	}
	return out
}
func (v vaultValue) clone() vaultValue {
	v.bytes = append([]byte(nil), v.bytes...)
	v.items = vaultCloneValues(v.items)
	v.fields = vaultCloneFields(v.fields)
	return v
}
