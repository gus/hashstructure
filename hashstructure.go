package hashstructure

import (
	"encoding/binary"
	"fmt"
	"hash"
	"hash/fnv"
	"reflect"
	"strings"
	"time"
)

// HashOptions are options that are available for hashing.
type HashOptions struct {
	// Hasher is the hash function to use. If this isn't set, it will
	// default to FNV.
	Hasher hash.Hash64

	// TagName is the struct tag to look at when hashing the structure.
	// By default this is "hash".
	TagName string

	// ZeroNil is flag determining if nil pointer should be treated equal
	// to a zero value of pointed type. By default this is false.
	ZeroNil bool

	// IgnoreZeroValue is determining if zero value fields should be
	// ignored for hash calculation.
	IgnoreZeroValue bool

	// SlicesAsSets assumes that a `set` tag is always present for slices.
	// Default is false (in which case the tag is used instead)
	SlicesAsSets bool

	// UseStringer will attempt to use fmt.Stringer always. If the struct
	// doesn't implement fmt.Stringer, it'll fall back to trying usual tricks.
	// If this is true, and the "string" tag is also set, the tag takes
	// precedence (meaning that if the type doesn't implement fmt.Stringer, we
	// panic)
	UseStringer bool
}

// Format specifies the hashing process used. Different formats typically
// generate different hashes for the same value and have different properties.
type Format uint

const (
	// To disallow the zero value
	formatInvalid Format = iota

	// FormatV1 is the format used in v1.x of this library. This has the
	// downsides noted in issue #18 but allows simultaneous v1/v2 usage.
	FormatV1

	// FormatV2 is the current recommended format and fixes the issues
	// noted in FormatV1.
	FormatV2

	formatMax // so we can easily find the end
)

// Hash returns the hash value of an arbitrary value.
//
// If opts is nil, then default options will be used. See HashOptions
// for the default values. The same *HashOptions value cannot be used
// concurrently. None of the values within a *HashOptions struct are
// safe to read/write while hashing is being done.
//
// The "format" is required and must be one of the format values defined
// by this library. You should probably just use "FormatV2". This allows
// generated hashes uses alternate logic to maintain compatibility with
// older versions.
//
// Notes on the value:
//
//   - Unexported fields on structs are ignored and do not affect the
//     hash value.
//
//   - Adding an exported field to a struct with the zero value will change
//     the hash value.
//
// For structs, the hashing can be controlled using tags. For example:
//
//	struct {
//	    Name string
//	    UUID string `hash:"ignore"`
//	}
//
// The available tag values are:
//
//   - "ignore" or "-" - The field will be ignored and not affect the hash code.
//
//   - "set" - The field will be treated as a set, where ordering doesn't
//     affect the hash code. This only works for slices.
//
//   - "string" - The field will be hashed as a string, only works when the
//     field implements fmt.Stringer
func Hash(v interface{}, format Format, opts *HashOptions) (uint64, error) {
	// Validate our format
	if format <= formatInvalid || format >= formatMax {
		return 0, &ErrFormat{}
	}

	// Create default options
	if opts == nil {
		opts = &HashOptions{}
	}
	if opts.Hasher == nil {
		opts.Hasher = fnv.New64()
	}
	if opts.TagName == "" {
		opts.TagName = "hash"
	}

	// Reset the hash
	opts.Hasher.Reset()

	// Create our walker and walk the structure
	w := &walker{
		format:          format,
		h:               opts.Hasher,
		tag:             opts.TagName,
		zeronil:         opts.ZeroNil,
		ignorezerovalue: opts.IgnoreZeroValue,
		sets:            opts.SlicesAsSets,
		stringer:        opts.UseStringer,
	}
	return w.visit(reflect.ValueOf(v), nil)
}

type walker struct {
	format          Format
	h               hash.Hash64
	tag             string
	zeronil         bool
	ignorezerovalue bool
	sets            bool
	stringer        bool
}

type visitOpts struct {
	// Flags are a bitmask of flags to affect behavior of this visit
	Flags fieldTag

	// Information about the struct containing this field
	Struct      interface{}
	StructField string
}

var timeType = reflect.TypeOf(time.Time{})

func (w *walker) visit(v reflect.Value, opts *visitOpts) (uint64, error) {
	t := reflect.TypeOf(0)

	// Loop since these can be wrapped in multiple layers of pointers
	// and interfaces.
	for {
		// If we have an interface, dereference it. We have to do this up
		// here because it might be a nil in there and the check below must
		// catch that.
		if v.Kind() == reflect.Interface {
			v = v.Elem()
			continue
		}

		if v.Kind() == reflect.Ptr {
			if w.zeronil {
				t = v.Type().Elem()
			}
			v = reflect.Indirect(v)
			continue
		}

		break
	}

	// If it is nil, treat it like a zero.
	if !v.IsValid() {
		v = reflect.Zero(t)
	}

	// Binary writing can use raw ints, we have to convert to
	// a sized-int, we'll choose the largest...
	switch v.Kind() {
	case reflect.Int:
		v = reflect.ValueOf(int64(v.Int()))
	case reflect.Uint:
		v = reflect.ValueOf(uint64(v.Uint()))
	case reflect.Bool:
		var tmp int8
		if v.Bool() {
			tmp = 1
		}
		v = reflect.ValueOf(tmp)
	}

	k := v.Kind()

	// We can shortcut numeric values by directly binary writing them
	if k >= reflect.Int && k <= reflect.Complex64 {
		// A direct hash calculation
		w.h.Reset()
		err := binary.Write(w.h, binary.LittleEndian, v.Interface())
		return w.h.Sum64(), err
	}

	switch v.Type() {
	case timeType:
		w.h.Reset()
		b, err := v.Interface().(time.Time).MarshalBinary()
		if err != nil {
			return 0, err
		}

		err = binary.Write(w.h, binary.LittleEndian, b)
		return w.h.Sum64(), err
	}

	switch k {
	case reflect.Array:
		var h uint64
		l := v.Len()
		for i := 0; i < l; i++ {
			current, err := w.visit(v.Index(i), nil)
			if err != nil {
				return 0, err
			}

			h = hashUpdateOrdered(w.h, h, current)
		}

		return h, nil

	case reflect.Map:
		if opts != nil && opts.Flags.Omitempty() && v.Len() == 0 {
			return 0, nil
		}

		var includeMap IncludableMap
		if opts != nil && opts.Struct != nil {
			if v, ok := opts.Struct.(IncludableMap); ok {
				includeMap = v
			}
		}

		// Build the hash for the map. We do this by XOR-ing all the key
		// and value hashes. This makes it deterministic despite ordering.
		var h uint64
		for _, k := range v.MapKeys() {
			v := v.MapIndex(k)
			if includeMap != nil {
				incl, err := includeMap.HashIncludeMap(
					opts.StructField, k.Interface(), v.Interface())
				if err != nil {
					return 0, err
				}
				if !incl {
					continue
				}
			}

			kh, err := w.visit(k, nil)
			if err != nil {
				return 0, err
			}
			vh, err := w.visit(v, nil)
			if err != nil {
				return 0, err
			}

			fieldHash := hashUpdateOrdered(w.h, kh, vh)
			h = hashUpdateUnordered(h, fieldHash)
		}

		if w.format != FormatV1 {
			// Important: read the docs for hashFinishUnordered
			h = hashFinishUnordered(w.h, h)
		}

		return h, nil

	case reflect.Struct:
		parent := v.Interface()
		var include Includable
		if impl, ok := parent.(Includable); ok {
			include = impl
		}

		if impl, ok := parent.(Hashable); ok {
			return impl.Hash()
		}

		// If we can address this value, check if the pointer value
		// implements our interfaces and use that if so.
		if v.CanAddr() {
			vptr := v.Addr()
			parentptr := vptr.Interface()
			if impl, ok := parentptr.(Includable); ok {
				include = impl
			}

			if impl, ok := parentptr.(Hashable); ok {
				return impl.Hash()
			}
		}

		t := v.Type()
		h, err := w.visit(reflect.ValueOf(t.Name()), nil)
		if err != nil {
			return 0, err
		}

		l := v.NumField()
		for i := 0; i < l; i++ {
			if innerV := v.Field(i); v.CanSet() || t.Field(i).Name != "_" {
				// var f visitFlag
				fieldType := t.Field(i)
				if fieldType.PkgPath != "" {
					continue // unexported
				}

				tag := parseFieldTag(fieldType.Tag.Get(w.tag))
				if tag.Ignore() {
					// explicitly ignore this field
					continue
				}

				if tag.Stringer() || w.stringer {
					// if string is set, use the string value
					if impl, ok := innerV.Interface().(fmt.Stringer); ok {
						innerV = reflect.ValueOf(impl.String())
					} else if tag.Stringer() {
						// We only show this error if the tag explicitly
						// requests a stringer.
						return 0, &ErrNotStringer{
							Field: v.Type().Field(i).Name,
						}
					}
				}

				if (w.ignorezerovalue || tag.Omitempty()) && innerV.IsZero() {
					// ignore/omit this field because it has a zero value
					continue
				}

				// Check if we implement includable and check it
				if include != nil {
					incl, err := include.HashInclude(fieldType.Name, innerV)
					if err != nil {
						return 0, err
					} else if !incl {
						continue
					}
				}

				vh, err := w.visit(innerV, &visitOpts{
					Flags:       tag,
					Struct:      parent,
					StructField: fieldType.Name,
				})
				if err != nil {
					return 0, err
				} else if vh == 0 && tag.Omitempty() {
					continue
				}

				kh, err := w.visit(reflect.ValueOf(fieldType.Name), nil)
				if err != nil {
					return 0, err
				}

				h = hashUpdateUnordered(h, hashUpdateOrdered(w.h, kh, vh))
			}

			if w.format != FormatV1 {
				// Important: read the docs for hashFinishUnordered
				h = hashFinishUnordered(w.h, h)
			}
		}

		return h, nil

	case reflect.Slice:
		// We have two behaviors here. If it isn't a set, then we just
		// visit all the elements. If it is a set, then we do a deterministic
		// hash code.
		var h uint64
		set := opts != nil && opts.Flags.IsSet()

		l := v.Len()
		for i := 0; i < l; i++ {
			current, err := w.visit(v.Index(i), nil)
			if err != nil {
				return 0, err
			}

			if set || w.sets {
				h = hashUpdateUnordered(h, current)
			} else {
				h = hashUpdateOrdered(w.h, h, current)
			}
		}

		if set && w.format != FormatV1 {
			// Important: read the docs for hashFinishUnordered
			h = hashFinishUnordered(w.h, h)
		}

		return h, nil

	case reflect.String:
		// Directly hash
		w.h.Reset()
		_, err := w.h.Write([]byte(v.String()))
		return w.h.Sum64(), err

	default:
		return 0, fmt.Errorf("unknown kind to hash: %s", k)
	}

}

type fieldTag uint

func (ft fieldTag) IsValid() bool   { return ft > fieldTagInvalid }
func (ft fieldTag) IsSet() bool     { return ft&fieldTagSet > 0 }
func (ft fieldTag) Omitempty() bool { return ft&fieldTagOmitempty > 0 }
func (ft fieldTag) Ignore() bool    { return ft&fieldTagIgnore > 0 }
func (ft fieldTag) Stringer() bool  { return ft&fieldTagStringer > 0 }

const (
	fieldTagInvalid   fieldTag = 0
	fieldTagSet                = 1
	fieldTagOmitempty          = 1 << 1
	fieldTagIgnore             = 1 << 2
	fieldTagStringer           = 1 << 3
)

func parseFieldTag(tagVal string) fieldTag {
	ft := fieldTagInvalid
	for _, flag := range strings.Split(tagVal, ",") {
		switch flag {
		case "set":
			ft |= fieldTagSet
		case "omitempty":
			ft |= fieldTagOmitempty
		case "ignore", "-":
			ft |= fieldTagIgnore
		case "string":
			ft |= fieldTagStringer
		}
	}
	return ft
}

func hashUpdateOrdered(h hash.Hash64, a, b uint64) uint64 {
	// For ordered updates, use a real hash function
	h.Reset()

	// We just panic if the binary writes fail because we are writing
	// an int64 which should never be fail-able.
	e1 := binary.Write(h, binary.LittleEndian, a)
	e2 := binary.Write(h, binary.LittleEndian, b)
	if e1 != nil {
		panic(e1)
	}
	if e2 != nil {
		panic(e2)
	}

	return h.Sum64()
}

func hashUpdateUnordered(a, b uint64) uint64 {
	return a ^ b
}

// After mixing a group of unique hashes with hashUpdateUnordered, it's always
// necessary to call hashFinishUnordered. Why? Because hashUpdateUnordered
// is a simple XOR, and calling hashUpdateUnordered on hashes produced by
// hashUpdateUnordered can effectively cancel out a previous change to the hash
// result if the same hash value appears later on. For example, consider:
//
//	hashUpdateUnordered(hashUpdateUnordered("A", "B"), hashUpdateUnordered("A", "C")) =
//	H("A") ^ H("B")) ^ (H("A") ^ H("C")) =
//	(H("A") ^ H("A")) ^ (H("B") ^ H(C)) =
//	H(B) ^ H(C) =
//	hashUpdateUnordered(hashUpdateUnordered("Z", "B"), hashUpdateUnordered("Z", "C"))
//
// hashFinishUnordered "hardens" the result, so that encountering partially
// overlapping input data later on in a different context won't cancel out.
func hashFinishUnordered(h hash.Hash64, a uint64) uint64 {
	h.Reset()

	// We just panic if the writes fail
	e1 := binary.Write(h, binary.LittleEndian, a)
	if e1 != nil {
		panic(e1)
	}

	return h.Sum64()
}
