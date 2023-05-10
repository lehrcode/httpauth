package main

import (
	"flag"
	"fmt"
	"github.com/lehrcode/httpauth/htpasswd"
	"log"
	"net/http"
)

func requireBasicAuth(next http.Handler, htpasswd *htpasswd.Htpasswd) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)
		if usrname, pwdhash, auth := r.BasicAuth(); auth {
			if err := htpasswd.Verify(usrname, pwdhash); err != nil {
				log.Print(err)
				http.Error(w, "access denied", http.StatusForbidden)
				return
			}
		} else {
			w.Header().Set("WWW-Authenticate", "Basic")
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
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

	http.Handle("/", requireBasicAuth(http.FileServer(http.Dir(*directory)), h))

	log.Printf("Serving %s on %s:%d\n", *directory, *addr, *port)
	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", *addr, *port), nil); err != nil {
		log.Fatal(err)
	}
}
