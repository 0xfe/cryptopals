package cryptopals

import "testing"

func assertNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("want no error, got error: %v", err)
	}
}

func assertHasError(t *testing.T, err error) {
	if err == nil {
		t.Errorf("want error, got no error")
	}
}

func assertTrue(t *testing.T, got bool) {
	if !got {
		t.Errorf("want true, got false")
	}
}

func assertFalse(t *testing.T, got bool) {
	if got {
		t.Errorf("want false, got true")
	}
}

func assertEquals(t *testing.T, want interface{}, got interface{}) {
	if want != got {
		t.Errorf("want: %v, got %v", want, got)
	}
}
