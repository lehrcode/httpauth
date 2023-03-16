package htpasswd

import (
	"errors"
	"strings"
	"testing"
)

const htpasswdFile = "test:$2y$05$39jxwwgWTFsnkvx73HEmnuePNaLnFTCPNGa8iplsgoe7PO232fSrG"

func TestHtpasswd_Verify(t *testing.T) {
	h, _ := New(strings.NewReader(htpasswdFile))

	if err := h.Verify("test", "test"); err != nil {
		t.Errorf("Verify() got error %q", err)
	}
}

func TestHtpasswd_Verify_ErrUserNotFound(t *testing.T) {
	h, _ := New(strings.NewReader(htpasswdFile))

	if err := h.Verify("foo", "bar"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("Verify() got error %q but want error %q", err, ErrUserNotFound)
	}
}
