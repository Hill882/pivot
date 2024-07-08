package handlers

import (
	"fmt"
	"net/http"
	"database/sql"
  "html/template"
  "time"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

type Job struct {
	ID          string    `json:"id"`
	JobName     string    `json:"job_name"`
	CompanyName string    `json:"company_name"`
	UserID      string    `json:"user_id"`
	CompanyID   string    `json:"company_id"`
	CreatedAt   time.Time `json:"created_at"`
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
      location := r.FormValue("location")
      companyName := r.FormValue("company_name")
      
      if confirmPassword != password {
        renderSignupTemplateWithError(w, "Passwords do not match", templates)
      }

      hashedPassword, err := hashPassword(password)
      if err != nil {
        renderSignupTemplateWithError(w, "Error creating account. Please try again", templates)
        return
      }

      query := `INSERT INTO admins (id, email, password, location, company_name, created_at)
                VALUES (gen_random_uuid(), $1, $2, $3, $4, CURRENT_TIMESTAMP)
                RETURNING id
                `
      var id string
      err = db.QueryRow(query, email, hashedPassword, location, companyName).Scan(&id)
      
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

      fmt.Println(id)
      //set session values
      session.Values["authenticated"] = true
      session.Values["user"] = email
      session.Values["user_id"] = id //each user will belong to a admin id
      session.Values["is_admin"] = true

      err = session.Save(r, w)
      if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
      }

      http.Redirect(w, r, "/map/", http.StatusSeeOther)
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

      var id, admin_id, storedPassword string
      var isAdmin bool
      err = db.QueryRow("SELECT password FROM users WHERE email = $1", email).Scan(&userId, &storedPassword, &location, &companyName, &isAdmin)
      if err != nil {
        if err == sql.ErrNoRows {
          renderLoginTemplateWithError(w, "Incorrect email or password", templates)
        } else {
          http.Error(w, "Database error", http.StatusInternalServerError)
        }
        return
      } else if !checkPasswordHash(password, storedPassword) {
        renderLoginTemplateWithError(w, "Incorrect password", templates)
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
      session.Values["is_admin"].isAdmin

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

func hashPassword(password string) (string, error) {
  hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
  if err != nil {
    return "", err
  }
  return string(hashedPassword), nil
}

func checkPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

func handleGetJobs(db *sql.DB, templates *template.Template) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
      adminID := r.Context().Value("admin_id").(string)
      query := `SELECT id, job_name, company_name, created_at FROM jobs WHERE admin_id = $1`
      rows, err := db.Query(query, adminID)
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

      err = templates.ExecuteTemplate(w, "jobs.html", jobs)
      if err != nil {
          http.Error(w, "Template rendering error", http.StatusInternalServerError)
      }
  }
}

//func handleGetJobs(w http.ResponseWriter, r *http.Request) {
//  // need to only select jobs from database that belong to company
//  session, err := store.Get(r, "SESSION_KEY")
//  if err != nil {
//    http.Error(w, err.Error(), http.StatusInternalServerError)
//    return
//  }
//  
//  companyId, ok := session.Values["company_id"].(string)
//  if !ok {
//    http.Error(w, "unauthorized", http.StatusUnauthorized)
//  }
//  
//  query := `SELECT id, job_name, company_name, user_id, company_id, created_at FROM jobs where company_id = $1`
//
//  rows, err := db.Query(query, companyId)
//  if err != nil {
//    http.Error(w, "Failed to retrieve jobs", http.StatusInternalServerError)
//    return
//  }
//  defer rows.Close()
//
//  var jobs []Job
//
//  for rows.Next() {
//    var job Job
//    if err := rows.Scan(&job.ID, &job.JobName, &job.CompanyName, &job.UserID, &job.CompanyID, &job.CreatedAt); err != nil {
//      http.Error(w, "Failed to scan for jobs", http.StatusInternalServerError)
//      return
//    }
//    jobs = append(jobs, job)
//  }
//
//  if err := rows.Err(); err != nil {
//    http.Error(w, "Failed to retrieve jobs", http.StatusInternalServerError)
//    return
//  
//
//  w.Header().Set("Content-Type", "application/json")
//  if err := json.NewEncoder(w).Encode(jobs); err != nil {
//    http.Error(w, "Failed to encode jobs", http.StatusInternalServerError)
//    return
//  }
//}

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

func HandleCreateJob(store *sessions.CookieStore) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    jobName := r.FormValue("job-name")
    companyName := r.FormValue("company-name")
    session, err := store.Get(r, "SESSION_KEY")
    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }

    if auth, ok := session.Values["authenticated"].(bool); ok && auth {
      http.Redirect(w, r, "/map", http.StatusSeeOther)
      return
    }

    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }

    _ = jobName
    _ = companyName
    var id = 1

    //id, err := insertJobIntoDb(jobName, companyName)
    //if err != nil {
    //	http.Error(w, err.Error(), http.StatusInternalServerError)
    //  return
    //}

    //fmt.Println(id)

    http.Redirect(w, r, fmt.Sprintf("/map/%s", id), http.StatusSeeOther)
  }
}

//func insertJobIntoDb(jobName, companyName, userId, companyId string, db *sql.Db) (string, error) {
//  query := `INSERT INTO jobs (id, job_name, company_name, user_id, company_id, created_at)
//            VALUES (gen_random_uuid(), $1, $2, $3, $4, CURRENT_TIMESTAMP)
//            RETURNING id
//           `
//  var id string
//  err := db.QueryRow(query, jobName, companyName, userId, companyId).Scan(&id)
//	//err := db.Exec(query, jobName, companyName).Scan(&id)
//  if err != nil {
//    log.Printf("Error inserting job into database: %v", err)
//    return "", err
//  }
//
//  return id, nil
//}
