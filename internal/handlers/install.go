package handlers

import (
	_ "embed"
	"net/http"
)

//go:embed install_script.sh
var installScript []byte

func ServeInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(installScript)
}
