package sessions

import (
	"crypto/rand"
	"encoding/base32"
	"log"
	"net/http"
	"sync"
	"time"
)

// https://www.crockford.com/base32.html
var crockfordBase32 = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

type Session struct {
	Timestamp time.Time
	values    map[string]string
}

func (s *Session) Get(key string) string {
	return s.values[key]
}

func (s *Session) Set(key, value string) {
	s.values[key] = value
}

type Store struct {
	CookieName string
	sessions   map[string]*Session
	Timeout    time.Duration
	mutex      sync.Mutex
}

func NewStore(cookieName string, timeout time.Duration) *Store {
	return &Store{
		CookieName: cookieName,
		sessions:   map[string]*Session{},
		Timeout:    timeout,
	}
}

func (s *Store) GetSession(w http.ResponseWriter, r *http.Request) *Session {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	var sessionCookie, _ = r.Cookie(s.CookieName)
	if sessionCookie == nil || s.sessions[sessionCookie.Value] == nil {
		randomBytes := make([]byte, 20)
		if _, err := rand.Read(randomBytes); err != nil {
			panic(err)
		}
		sessionID := crockfordBase32.EncodeToString(randomBytes)
		sessionCookie = &http.Cookie{
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
			Name:     s.CookieName,
			Value:    sessionID,
		}
		http.SetCookie(w, sessionCookie)
		s.sessions[sessionID] = &Session{
			Timestamp: time.Now(),
			values:    map[string]string{},
		}
	}
	return s.sessions[sessionCookie.Value]
}

func (s *Store) CollectGarbage() {
	log.Print("CollectGarbage()")
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for sessionID, session := range s.sessions {
		if time.Now().Sub(session.Timestamp) > s.Timeout {
			delete(s.sessions, sessionID)
		}
	}
}
