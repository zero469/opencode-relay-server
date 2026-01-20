package handlers

import (
	_ "embed"
	"net/http"
)

//go:embed install_script.sh
var installScript []byte

//go:embed install_script.ps1
var installScriptPS1 []byte

func ServeInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(installScript)
}

func ServeInstallScriptPS1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(installScriptPS1)
}
