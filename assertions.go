package cryptopals

import "testing"

func assertNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("want no error, got error: %v", err)
	}
}

func assertEquals(t *testing.T, want interface{}, got interface{}) {
	if want != got {
		t.Errorf("want: %v, got %v", want, got)
	}
}
