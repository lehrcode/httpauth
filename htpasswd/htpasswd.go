package htpasswd

import (
	"bufio"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"io"
	"os"
	"strings"
)

var (
	ErrUnsupportedHash = errors.New("unsupported hash")
	ErrUserNotFound    = errors.New("user not found")
)

type Htpasswd struct {
	Users map[string]string
}

func (h Htpasswd) Verify(usrname, passwd string) error {
	if pwdhash, found := h.Users[strings.ToLower(strings.TrimSpace(usrname))]; found {
		if strings.HasPrefix(pwdhash, "$2") {
			return bcrypt.CompareHashAndPassword([]byte(pwdhash), []byte(passwd))
		} else {
			return ErrUnsupportedHash
		}
	}
	return ErrUserNotFound
}

func New(rd io.Reader) (*Htpasswd, error) {
	h := &Htpasswd{Users: make(map[string]string)}
	sc := bufio.NewScanner(rd)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "#") {
			fields := strings.SplitN(line, ":", 2)
			h.Users[strings.ToLower(strings.TrimSpace(fields[0]))] = strings.TrimSpace(fields[1])
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return h, nil
}

func NewFromFile(filename string) (*Htpasswd, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	return New(fd)
}
