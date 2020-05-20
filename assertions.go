package cryptopals

import (
	"fmt"
	"runtime/debug"
	"testing"
)

func assertNoError(t *testing.T, err error) {
	if err != nil {
		fmt.Printf("FAIL: want no error, got error: %v\n%s", err, string(debug.Stack()))
		t.Fatalf("want no error, got error: %v\n%s", err, string(debug.Stack()))
	}
}

func assertHasError(t *testing.T, err error) {
	if err == nil {
		fmt.Printf("want error, got no error\n%s", string(debug.Stack()))
		t.Fatalf("want error, got no error\n%s", string(debug.Stack()))
	}
}

func assertTrue(t *testing.T, got bool) {
	if !got {
		fmt.Printf("want true, got false\n%s", string(debug.Stack()))
		t.Fatalf("want true, got false\n%s", string(debug.Stack()))
	}
}

func assertFalse(t *testing.T, got bool) {
	if got {
		fmt.Printf("want false, got true\n%s", string(debug.Stack()))
		t.Fatalf("want false, got true\n%s", string(debug.Stack()))
	}
}

func assertEquals(t *testing.T, want interface{}, got interface{}) {
	if want != got {
		fmt.Printf("want: %v, got %v\n%s", want, got, string(debug.Stack()))
		t.Fatalf("want: %v, got %v\n%s", want, got, string(debug.Stack()))
	}
}
