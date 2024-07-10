package handlers

import (
	"database/sql"
  "encoding/json"
  "html/template"
  "path/filepath"
	"fmt"
  "io"
	"net/http"
  "strings"
  "time"
  "log"
  "os"
	"github.com/gorilla/sessions"
  "github.com/gorilla/mux"
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
    // Check if user session exists
    session, err := store.Get(r, "SESSION_KEY")
    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }

    userId, ok := session.Values["user_id"].(string)
    if !ok {
        http.Error(w, "User ID not found in context", http.StatusUnauthorized)
        return
    }

    isAdmin, ok := session.Values["admin"].(bool)
    if !ok {
        http.Error(w, "Admin status not found in context", http.StatusUnauthorized)
        return
    }

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

    if len(jobs) == 0 {
      jobs = []Job{} // Ensure jobs is explicitly set to an empty array
    }
    json.NewEncoder(w).Encode(jobs)

    //jsonJobs, err := json.Marshal(jobs)
    //fmt.Println(jsonJobs)
    //if err != nil {
    //  http.Error(w, "Failed to serialize jobs", http.StatusInternalServerError)
    //  return
    //}

    // Set content type and send JSON response
    //w.Header().Set("Content-Type", "application/json")
    //w.WriteHeader(http.StatusOK)
    //json.NewEncoder(w).Encode(jobs)
  }
}

func HandleGetMapWithJob(templates *template.Template) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    data := struct {
      ShowTools bool

    }{
      ShowTools: true,
    }
    err := templates.ExecuteTemplate(w, "index.html", data)
    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }
  }
}

func HandleGetMap(templates *template.Template) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    data := struct {
      ShowTools bool
    }{
      ShowTools: false,
    }
    err := templates.ExecuteTemplate(w, "index.html", data)
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
    session, err := store.Get(r, "SESSION_KEY")
    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }

    userId, ok := session.Values["user_id"].(string)
    if !ok {
        http.Error(w, "User ID not found in context", http.StatusUnauthorized)
        return
    }

    isAdmin, ok := session.Values["admin"].(bool)
    if !ok {
        http.Error(w, "Admin status not found in context", http.StatusUnauthorized)
        return
    }

    jobName := r.FormValue("job-name")
    companyName := r.FormValue("company-name")

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

func HandleUploadLas(store *sessions.CookieStore, db *sql.DB) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    jobId := vars["id"]

    var adminId string
    query := `SELECT admin_id FROM jobs WHERE id = $1`
    err := db.QueryRow(query, jobId).Scan(&adminId)
    if err != nil {
      http.Error(w, "Error getting admin id from jobs", http.StatusInternalServerError)
      return
    }

    // Ensure Content-Type is multipart/form-data
    if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
      http.Error(w, "Content-Type must be multipart/form-data", http.StatusBadRequest)
      return
    }

    // Parse the multipart form with a max memory of 32 MB
    if err := r.ParseMultipartForm(32 << 20); err != nil {
      http.Error(w, "Unable to parse form", http.StatusBadRequest)
      return
    }

    // Retrieve the file from the form input
    file, header, err := r.FormFile("file")
    if err != nil {
      http.Error(w, "Unable to get file", http.StatusBadRequest)
      return
    }
    defer file.Close()

    // Check if the file has a .las extension
    name := strings.ToLower(header.Filename)
    if !strings.HasSuffix(name, ".las") {
      http.Error(w, "File is not a LAS file", http.StatusBadRequest)
      return
    }

    serverDir := os.Getenv("SERVER_DIR")

    folderPath := filepath.Join(serverDir, adminId)

    if err := os.MkdirAll(folderPath, os.ModePerm); err != nil {
      http.Error(w, "Error creating uploads folder", http.StatusInternalServerError)
      return
    }

    filePath := filepath.Join(folderPath, fmt.Sprintf("%s.las", jobId))

    outFile, err := os.Create(filePath)
    if err != nil {
      http.Error(w, "Unable to create file on server", http.StatusInternalServerError)
      return
    }
  
    defer outFile.Close()

    if _, err := io.Copy(outFile, file); err != nil {
      http.Error(w, "Error saving file", http.StatusInternalServerError)
      return
    }
    
    w.Write([]byte("LAS file uploaded and processed successfully"))
  }
}


func isLasFile(data []byte) bool {
  const lasHeader = ".lasf"
  if len(data) < len(lasHeader) {
    return false
  }
  return string(data[:len(lasHeader)]) == lasHeader
}
