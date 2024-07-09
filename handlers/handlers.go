package handlers

import (
	"database/sql"
  "encoding/json"
  "html/template"
	"fmt"
	"net/http"
  "time"
  "log"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
  _ "github.com/lib/pq"
)

type Job struct {
	ID          string    `json:"id"`
	JobName     string    `json:"job_name"`
	CompanyName string    `json:"company_name"`
	UserID      string    `json:"user_id"`
	CompanyID   string    `json:"company_id"`
	CreatedAt   time.Time `json:"created_at"`
}

func hashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

func HandleSignup(store *sessions.CookieStore, templates *template.Template, db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
      if store == nil || templates == nil || db == nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
      }

    if r.Method == "GET" {
      err := templates.ExecuteTemplate(w, "signup.html", nil)
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
      confirmPassword := r.FormValue("confirm_password")
      
      if confirmPassword != password {
        renderSignupTemplateWithError(w, "Passwords do not match", templates)
      }

      hashedPassword, err := hashPassword(password)
      if err != nil {
        http.Error(w, "Unable to hash password", http.StatusInternalServerError)
        return
      }

      query := `INSERT INTO admins (id, email, password, created_at)
                VALUES (gen_random_uuid(), $1, $2, CURRENT_TIMESTAMP)
                RETURNING id
               `
      var id string
      err = db.QueryRow(query, email, hashedPassword).Scan(&id)


      if err != nil {
        renderSignupTemplateWithError(w, "Error creating account. Please try again", templates)
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
      session.Values["user_email"] = email
      session.Values["user_id"] = id 
      session.Values["admin"] = true

      err = session.Save(r, w)
      if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
      }

      http.Redirect(w, r, "/map", http.StatusSeeOther)
    }
  }
}


func HandleLogin(store *sessions.CookieStore, templates *template.Template, db *sql.DB) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    if store == nil || templates == nil || db == nil {
      http.Error(w, "Internal server error", http.StatusInternalServerError)
      return
    }

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

      var userId, storedPassword string
      var isAdmin bool
      // check if the user is a admin or not
      err = db.QueryRow("SELECT id, password FROM users WHERE email = $1", email).Scan(&userId, &storedPassword)
			if err != nil {
				// If user not found in users table, check admins table
				err = db.QueryRow("SELECT id, password FROM admins WHERE email = $1", email).Scan(&userId, &storedPassword)
				if err != nil {
					if err == sql.ErrNoRows {
						renderLoginTemplateWithError(w, "Incorrect email or password", templates)
					} else {
						http.Error(w, "Database error", http.StatusInternalServerError)
					}
					return
				}
				// User is found in admins table, set isAdmin to true
				isAdmin = true
			}

      if !checkPasswordHash(password, storedPassword) {
        renderLoginTemplateWithError(w, "Error creating account. Please try again", templates)
        return
      }
      
      // create a new session
      session, err := store.Get(r, "SESSION_KEY")
      if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
      }

      // check cookies match
      //set session values
      session.Values["authenticated"] = true
      session.Values["user_email"] = email
      session.Values["user_id"] = userId
      if isAdmin {
        session.Values["admin"] = true
      } else {
        session.Values["admin"] = false
      }

      err = session.Save(r, w)
      if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
      }

      http.Redirect(w, r, "/map", http.StatusSeeOther)
    }
  }
}

type loginSuccess struct {
	Success bool
	Error string
}

func renderLoginTemplateWithError(w http.ResponseWriter, errorMessage string, templates *template.Template) {
  data := loginSuccess{
    Success: false,
    Error:   errorMessage,
  }
  err := templates.ExecuteTemplate(w, "login.html", data)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }
}

func renderSignupTemplateWithError(w http.ResponseWriter, errorMessage string, templates *template.Template) {
  data := loginSuccess{
    Success: false,
    Error:   errorMessage,
  }
  err := templates.ExecuteTemplate(w, "signup.html", data)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }
}

func HandleGetJobs(store *sessions.CookieStore, db *sql.DB, templates *template.Template) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    userId := r.Context().Value("user_id").(string)
    //if !ok || userId == "" {
    //  http.Error(w, "User ID not found in context", http.StatusUnauthorized)
    //  return
    //}
    isAdmin := r.Context().Value("is_admin").(bool)
    //if !ok {
    //  http.Error(w, "Admin status not found in context", http.StatusUnauthorized)
    //  return
    //}

    var adminId string


    if isAdmin {
      adminId = userId
    } else {
      err := db.QueryRow(`SELECT admin_id FROM users WHERE id = $1`, userId).Scan(&adminId)
      if err != nil {
        http.Error(w, "Error fetching admin id from database", http.StatusInternalServerError)
        return
      }
    }

    query := `SELECT id, job_name, company_name, created_at FROM jobs WHERE admin_id = $1`
    rows, err := db.Query(query, adminId)
    if err != nil {
      http.Error(w, "Database error", http.StatusInternalServerError)
      return
    }
    defer rows.Close()

    var jobs []Job
    for rows.Next() {
      var job Job
      err := rows.Scan(&job.ID, &job.JobName, &job.CompanyName, &job.CreatedAt)
      if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
      }
      jobs = append(jobs, job)
    }

    jsonJobs, err := json.Marshal(jobs)

    if err != nil {
      http.Error(w, "Failed to serialize jobs", http.StatusInternalServerError)
      return
    }

    // Set content type and send JSON response
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    w.Write(jsonJobs)
  }
}

func HandleGetMapWithJob(templates *template.Template) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    err := templates.ExecuteTemplate(w, "index.html", nil)
    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }
  }
}

func HandleGetMap(templates *template.Template) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    err := templates.ExecuteTemplate(w, "index.html", nil)
    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }
  }
}

func HandleLogout(store *sessions.CookieStore) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    session, err := store.Get(r, "SESSION_KEY")
    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }

    // Revoke users authentication
    session.Values["authenticated"] = false
    session.Save(r, w)

    http.Redirect(w, r, "/login", http.StatusSeeOther)
  }
}


func HandleGetContactPage(templates *template.Template) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    err := templates.ExecuteTemplate(w, "contact.html", nil)
    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }
  }
}

func HandleCreateJob(store *sessions.CookieStore, db *sql.DB) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    jobName := r.FormValue("job-name")
    companyName := r.FormValue("company-name")

    userId := r.Context().Value("user_id").(string)
    isAdmin := r.Context().Value("is_admin").(bool)

    var adminId string

    if isAdmin {
      adminId = userId
    } else {
      err := db.QueryRow(`SELECT admin_id FROM users WHERE id = $1`, userId).Scan(&adminId)
      if err != nil {
        http.Error(w, "Error fetching admin id from database", http.StatusInternalServerError)
        return
      }
    }

    id, err := insertJobIntoDb(jobName, companyName, adminId, db)
    if err != nil {
    	http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }

    http.Redirect(w, r, fmt.Sprintf("/map/%s", id), http.StatusSeeOther)
  }
}

func insertJobIntoDb(jobName, companyName, adminId string, db *sql.DB) (string, error) {
  query := `INSERT INTO jobs (id, job_name, company_name, admin_id, created_at)
            VALUES (gen_random_uuid(), $1, $2, $3, CURRENT_TIMESTAMP)
            RETURNING id
           `
  var id string
  err := db.QueryRow(query, jobName, companyName, adminId).Scan(&id)
  if err != nil {
    log.Printf("Error inserting job into database: %v", err)
    return "", err
  }

  return id, nil
}
