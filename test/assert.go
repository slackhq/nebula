package test

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

// AssertDeepCopyEqual checks to see if two variables have the same values but DO NOT share any memory
// There is currently a special case for `time.loc` (as this code traverses into unexported fields)
func AssertDeepCopyEqual(t *testing.T, a any, b any) {
	v1 := reflect.ValueOf(a)
	v2 := reflect.ValueOf(b)

	if !assert.Equal(t, v1.Type(), v2.Type()) {
		return
	}

	traverseDeepCopy(t, v1, v2, v1.Type().String())
}

func traverseDeepCopy(t *testing.T, v1 reflect.Value, v2 reflect.Value, name string) bool {
	if v1.Type() == v2.Type() && v1.Type() == reflect.TypeOf(netip.Addr{}) {
		// Ignore netip.Addr types since they reuse an interned global value
		return false
	}

	switch v1.Kind() {
	case reflect.Array:
		for i := 0; i < v1.Len(); i++ {
			if !traverseDeepCopy(t, v1.Index(i), v2.Index(i), fmt.Sprintf("%s[%v]", name, i)) {
				return false
			}
		}
		return true

	case reflect.Slice:
		if v1.IsNil() || v2.IsNil() {
			return assert.Equal(t, v1.IsNil(), v2.IsNil(), "%s are not both nil %+v, %+v", name, v1, v2)
		}

		if !assert.Equal(t, v1.Len(), v2.Len(), "%s did not have the same length", name) {
			return false
		}

		// A slice with cap 0
		if v1.Cap() != 0 && !assert.NotEqual(t, v1.Pointer(), v2.Pointer(), "%s point to the same slice %v == %v", name, v1.Pointer(), v2.Pointer()) {
			return false
		}

		v1c := v1.Cap()
		v2c := v2.Cap()
		if v1c > 0 && v2c > 0 && v1.Slice(0, v1c).Slice(v1c-1, v1c-1).Pointer() == v2.Slice(0, v2c).Slice(v2c-1, v2c-1).Pointer() {
			return assert.Fail(t, "", "%s share some underlying memory", name)
		}

		for i := 0; i < v1.Len(); i++ {
			if !traverseDeepCopy(t, v1.Index(i), v2.Index(i), fmt.Sprintf("%s[%v]", name, i)) {
				return false
			}
		}
		return true

	case reflect.Interface:
		if v1.IsNil() || v2.IsNil() {
			return assert.Equal(t, v1.IsNil(), v2.IsNil(), "%s are not both nil", name)
		}
		return traverseDeepCopy(t, v1.Elem(), v2.Elem(), name)

	case reflect.Ptr:
		local := reflect.ValueOf(time.Local).Pointer()
		if local == v1.Pointer() && local == v2.Pointer() {
			return true
		}

		if !assert.NotEqual(t, v1.Pointer(), v2.Pointer(), "%s points to the same memory", name) {
			return false
		}

		return traverseDeepCopy(t, v1.Elem(), v2.Elem(), name)

	case reflect.Struct:
		for i, n := 0, v1.NumField(); i < n; i++ {
			if !traverseDeepCopy(t, v1.Field(i), v2.Field(i), name+"."+v1.Type().Field(i).Name) {
				return false
			}
		}
		return true

	case reflect.Map:
		if v1.IsNil() || v2.IsNil() {
			return assert.Equal(t, v1.IsNil(), v2.IsNil(), "%s are not both nil", name)
		}

		if !assert.Equal(t, v1.Len(), v2.Len(), "%s are not the same length", name) {
			return false
		}

		if !assert.NotEqual(t, v1.Pointer(), v2.Pointer(), "%s point to the same memory", name) {
			return false
		}

		for _, k := range v1.MapKeys() {
			val1 := v1.MapIndex(k)
			val2 := v2.MapIndex(k)
			if !assert.True(t, val1.IsValid(), "%s is an invalid key in %s", k, name) {
				return false
			}

			if !assert.True(t, val2.IsValid(), "%s is an invalid key in %s", k, name) {
				return false
			}

			if !traverseDeepCopy(t, val1, val2, name+fmt.Sprintf("%s[%s]", name, k)) {
				return false
			}
		}

		return true

	default:
		if v1.CanInterface() && v2.CanInterface() {
			return assert.Equal(t, v1.Interface(), v2.Interface(), "%s was not equal", name)
		}

		e1 := reflect.NewAt(v1.Type(), unsafe.Pointer(v1.UnsafeAddr())).Elem().Interface()
		e2 := reflect.NewAt(v2.Type(), unsafe.Pointer(v2.UnsafeAddr())).Elem().Interface()

		return assert.Equal(t, e1, e2, "%s (unexported) was not equal", name)
	}
}
