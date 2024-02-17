package main

import (
	"bytes"
	"html/template"
	"net/http"
	"noxway-admin/fetcher"

	log "github.com/sirupsen/logrus"
)
var (
	Services *fetcher.Services
	Config   *fetcher.ConfigStruct
)
func main() {
	// Lade die Konfiguration
	var err error
	Config, err = fetcher.LoadConfig("../config/config_global.json")
	if err != nil {
		log.Fatalln("Error loading config:", err)
	}
	// Lade die Services
	Services, err = fetcher.LoadConfigService("../config/config_service.json")
	if err != nil {
		log.Fatalln("Error loading services:", err)
	}
	// Starte den Webserver
	tmpl := template.Must(template.ParseGlob("templates/*.html"))

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Infoln("Request received /")
		// Überprüfen, ob der Benutzer eingeloggt ist
		if cookie, err := r.Cookie("loggedin"); err != nil || cookie.Value != "true" {
			// Wenn kein gültiger Cookie vorhanden ist, umleiten zu /login
			log.Infoln("No valid cookie found, redirecting to /login")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// Wenn der Benutzer eingeloggt ist, zum Dashboard umleiten
		http.Redirect(w, r, "/dashboard/", http.StatusSeeOther)
	})

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		log.Infoln("Request received /logout")
		// Löschen des Cookies und Umleitung zum Login
		http.SetCookie(w, &http.Cookie{
			Name:   "loggedin",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	http.HandleFunc("/dashboard/", dashboardHandler(tmpl))

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		log.Infoln("Request received /login", r.Method)
		if r.Method == "POST" {
			// Hier die Benutzerdaten überprüfen (vereinfachtes Beispiel)
			username := r.FormValue("username")
			password := r.FormValue("password")

			if username == "admin" && password == "admin" { // Beispielwerte
				log.Infoln("Login successful")
				// Login erfolgreich: Setze ein Cookie und leite zum Dashboard um
				http.SetCookie(w, &http.Cookie{
					Name:  "loggedin",
					Value: "true",
					Path:  "/",
				})
				http.Redirect(w, r, "/dashboard/", http.StatusSeeOther)
				return
			}
			log.Infoln("Login failed")

			// Login fehlgeschlagen: Zeige das Login-Formular erneut an
			tmpl.ExecuteTemplate(w, "login.html", map[string]bool{"LoginFailed": true})
			return
		}

		// GET-Anfrage: Zeige das Login-Formular an
		log.Infoln("Render first login page")
		terr := tmpl.ExecuteTemplate(w, "login.html", nil)
		if terr != nil {
			log.Errorln(terr.Error())
		}

	})

	http.ListenAndServe(":81", nil)
}

func dashboardHandler(tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, errA := r.Cookie("loggedin")
		if errA != nil || cookie.Value != "true" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		path := r.URL.Path
		var contentTemplate string
		var daten map[string]interface{}= nil
		switch path {
		case "/dashboard/config":
			contentTemplate = "config.html"
			daten = map[string]interface{}{
				"config": Config,
			}
			
		
		case "/dashboard/services":
			contentTemplate = "services.html"
		// Füge hier weitere Fälle für zusätzliche Inhalte hinzu
		default:
			contentTemplate = "flow.html" // Standard-Template oder Fehlerseite
		}

		// Vorbereiten des Inhalts als String
		var tmplContent bytes.Buffer
		if err := tmpl.ExecuteTemplate(&tmplContent, contentTemplate, daten); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Übergeben des Inhalts an das dashboard.html Template
		data := map[string]interface{}{
			"DynamicContent": template.HTML(tmplContent.String()),
			"daten":Config ,
		}
		if err := tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
