package htpasswd

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"io"
	"os"
	"strings"
)

var (
	ErrUnsupportedHash       = errors.New("unsupported hash")
	ErrUserNotFound          = errors.New("user not found")
	ErrPasswordHashMissmatch = errors.New("not the hash of the given password")
)

const shaPrefix = "{SHA}"

func CompareBase64Sha1HashAndPassword(hashedPassword string, password string) error {
	var base64hash = strings.TrimPrefix(hashedPassword, shaPrefix)
	var hash = make([]byte, 20)
	if _, err := base64.StdEncoding.Decode(hash, []byte(base64hash)); err != nil {
		return err
	}
	if [20]byte(hash) == sha1.Sum([]byte(password)) {
		return nil
	} else {
		return ErrPasswordHashMissmatch
	}
}

type Htpasswd struct {
	Users map[string]string
}

func (h Htpasswd) Verify(username, password string) error {
	if pwdhash, found := h.Users[strings.ToLower(strings.TrimSpace(username))]; found {
		if strings.HasPrefix(pwdhash, "$2") {
			return bcrypt.CompareHashAndPassword([]byte(pwdhash), []byte(password))
		} else if strings.HasPrefix(pwdhash, shaPrefix) {
			return CompareBase64Sha1HashAndPassword(pwdhash, password)
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
