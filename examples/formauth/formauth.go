package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"github.com/lehrcode/httpauth/htpasswd"
	"github.com/lehrcode/httpauth/sessions"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"
)

//go:embed loginform.gohtml
var loginTemplate string

func LoginHandler(h *htpasswd.Htpasswd, tpl *template.Template, sessionStore *sessions.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var username, password, message string
		if r.Method == http.MethodPost {
			username = strings.TrimSpace(r.PostFormValue("username"))
			password = strings.TrimSpace(r.PostFormValue("password"))
			if err := h.Verify(username, password); err != nil {
				log.Print(err)
				message = "Login error!"
			} else {
				var session = sessionStore.GetSession(w, r)
				session.Set("username", username)
				var redirectURI = session.Get("redirect_uri")
				if redirectURI == "" {
					redirectURI = "/"
				}
				http.Redirect(w, r, redirectURI, http.StatusFound)
				return
			}
		}
		var data = map[string]string{"username": username, "message": message}
		if err := tpl.ExecuteTemplate(w, "login", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}

func requireSession(next http.Handler, sessionStore *sessions.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)
		var session = sessionStore.GetSession(w, r)
		if session.Get("username") == "" {
			if r.URL.Path == "/favicon.ico" {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			} else {
				session.Set("redirect_uri", r.URL.Path)
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), "username", session.Get("username"))))
	})
}

func main() {
	addr := flag.String("addr", "", "address to serve on")
	port := flag.Int("port", 8000, "port to serve on")
	directory := flag.String("dir", ".", "the directory of static file to serve")
	htpasswdfile := flag.String("htpasswd", ".htpasswd", "htpasswd file name")
	flag.Parse()

	h, err := htpasswd.NewFromFile(*htpasswdfile)
	if err != nil {
		log.Fatal(err)
	}

	sessionStore := sessions.NewStore("SESSIONID", 5*time.Minute)
	go func() {
		for range time.Tick(5 * time.Minute) {
			sessionStore.CollectGarbage()
		}
	}()

	http.Handle("/login", LoginHandler(h, template.Must(template.New("login").Parse(loginTemplate)), sessionStore))
	http.Handle("/", requireSession(http.FileServer(http.Dir(*directory)), sessionStore))
	http.Handle("/whoami", requireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<!DOCTYPE html>\n<h1>Username: %s</h1>", r.Context().Value("username"))
	}), sessionStore))

	log.Printf("Serving %s on %s:%d\n", *directory, *addr, *port)
	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", *addr, *port), nil); err != nil {
		log.Fatal(err)
	}
}
