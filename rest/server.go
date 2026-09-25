package rest

import (
	"log"
	"net"
	"net/http"
	"path"
	"strconv"

	"github.com/codegangsta/negroni"
	"github.com/julienschmidt/httprouter"
	"github.com/nbio/httpcontext"

	"github.com/stunndard/cocosmail/core"
)

const (
	// Max size of the posted body
	body_read_limit = 1048576
)

// LaunchServer launches HTTP server
func LaunchServer() {
	// empty credentials would let anybody in
	if core.Cfg.GetRestServerLogin() == "" || core.Cfg.GetRestServerPasswd() == "" {
		log.Fatalln("REST server needs COCOSMAIL_REST_SERVER_LOGIN and COCOSMAIL_REST_SERVER_PASSWD")
	}

	router := httprouter.New()
	router.HandlerFunc("GET", "/ping", func(w http.ResponseWriter, req *http.Request) {
		httpWriteJson(w, []byte(`{"msg": "pong"}`))
	})

	// Users handlers
	addUsersHandlers(router)
	// Queue
	addQueueHandlers(router)

	// Server
	n := negroni.New(negroni.NewRecovery(), NewLogger())
	n.UseHandler(router)
	addr := net.JoinHostPort(core.Cfg.GetRestServerIp(), strconv.Itoa(core.Cfg.GetRestServerPort()))

	// TLS
	if core.Cfg.GetRestServerIsTls() {
		core.Logger.Info("httpd " + addr + " TLS launched")
		log.Fatalln(http.ListenAndServeTLS(addr, path.Join(getBasePath(), "ssl/web_server.crt"), path.Join(getBasePath(), "ssl/web_server.key"), n))
	} else {
		core.Logger.Info("httpd " + addr + " launched")
		log.Fatalln(http.ListenAndServe(addr, n))
	}
}

// wrapHandler puts httprouter.Params in query context
// in order to keep compatibily with http.Handler
func wrapHandler(h func(http.ResponseWriter, *http.Request)) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		httpcontext.Set(r, "params", ps)
		h(w, r)
	}
}

// getBasePath is a helper for retrieving app path
func getBasePath() string {
	return core.BaseDir()
}
