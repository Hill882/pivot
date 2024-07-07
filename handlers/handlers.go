package handlers

import (
	"fmt"
	"net/http"
	"database/sql"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
  // Check if user session exists
  session, err := store.Get(r, "SESSION_KEY")
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  if auth, ok := session.Values["authenticated"].(bool); ok && auth {
    http.Redirect(w, r, "/map", http.StatusSeeOther)
    return
  }
  
	if r.Method == "GET" {
		err := templates.ExecuteTemplate(w, "login.html", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")
		
		var storedPassword, userId, companyId string
		err = db.QueryRow("SELECT password FROM users WHERE email = $1", email).Scan(&storedPassword, &userId, &companyId)
		if err != nil {
      if err == sql.ErrNoRows {
        renderLoginTemplateWithError(w, "Incorrect email or password")
      } else {
        http.Error(w, "Database error", http.StatusInternalServerError)
      }
      return
		}

		if !checkPasswordHash(password, storedPassword) {
			fmt.Println("Invalid password")
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
    
    // create a new session
    session, err := store.Get(r, "SESSION_KEY")
    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }

    //set session values
    session.Values["authenticated"] = true
    session.Values["user"] = email
    session.Values["user_id"] = userId
    session.Values["company_id"].companyId

    err = session.Save(r, w)
    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }

    http.Redirect(w, r, "/map", http.StatusSeeOther)
	}
}

