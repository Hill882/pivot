package main


import (
    //"flag"
    "log"
    "html/template"
    "path/filepath"
    "net/http"
    "os"
    "fmt"
    "time"
    "encoding/json"
    "github.com/joho/godotenv"
    _ "github.com/lib/pq"
    "database/sql"
    "golang.org/x/crypto/bcrypt"
    "github.com/gorilla/sessions"
    "github.com/gorilla/mux"
    "github.com/Justin-Akridge/pivot/handlers" // Adjust this path as necessary
)

var db *sql.DB
var templates *template.Template
var store *sessions.CookieStore

func main() {
  r := mux.NewRouter()

  err := godotenv.Load()
  if err != nil {
      log.Fatal("Error loading .env file")
  }

  sessionKey := os.Getenv("SESSION_KEY")
  if sessionKey == "" {
    log.Fatal("Session key is missing")
  }

  store = sessions.NewCookieStore([]byte(sessionKey))

  apiKey := os.Getenv("GOOGLE_MAPS_API_KEY")
  if apiKey == "" {
      log.Fatal("GOOGLE_MAPS_API_KEY environment variable is not set")
  }

  // Load templates with API key
  templates = template.Must(template.New("").Funcs(template.FuncMap{
      "apiKey": func() string { return apiKey },
  }).ParseGlob(filepath.Join("static", "*.html")))

  r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

  // unprotected routes
  r.HandleFunc("/login", handlers.handleLogin).Methods("GET", "POST")
  r.HandleFunc("/logout", handleLogout).Methods("GET")
  r.HandleFunc("/contact", handleGetContactPage).Methods("GET")

  // protected routes
  // GET
  r.Handle("/map", authenticationMiddleware(store, http.HandlerFunc(handleGetMap))).Methods("GET")
  r.Handle("/map/{id}", authenticationMiddleware(store, http.HandlerFunc(handleGetMapWithJob))).Methods("GET")
  r.Handle("/createJob", authenticationMiddleware(store, http.HandlerFunc(handleCreateJob))).Methods("POST")
  r.Handle("/jobs", authenticationMiddleware(store, http.HandlerFunc(handleGetJobs))).Methods("GET")

  // Database connection
  dbUser := os.Getenv("DB_USER")
  dbPassword := os.Getenv("DB_PASSWORD")
  dbName := os.Getenv("DB_NAME")
  dbHost := os.Getenv("DB_HOST")
  dbPort := os.Getenv("DB_PORT")
  connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", dbUser, dbPassword, dbHost, dbPort, dbName)
  db, err = sql.Open("postgres", connStr)
  if err != nil {
    log.Fatal(err)
  }
  defer db.Close()

  err = db.Ping()
  if err != nil {
    log.Fatal("Cannot connect to the database:", err)
  }

  log.Println("Server started at http://localhost:8080/map")
  log.Fatal(http.ListenAndServe(":8080", r))
}

func authenticationMiddleware(store *sessions.CookieStore, next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    // prevent caching of sensitive pages
    w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
    w.Header().Set("Pragma", "no-cache")
    w.Header().Set("Expires", "0")

    session, err := store.Get(r, "SESSION_KEY")
    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }

    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
      http.Redirect(w, r, "/login", http.StatusSeeOther)
      return
    }

    next.ServeHTTP(w, r)
  })
}

type Job struct {
	ID          string    `json:"id"`
	JobName     string    `json:"job_name"`
	CompanyName string    `json:"company_name"`
	UserID      string    `json:"user_id"`
	CompanyID   string    `json:"company_id"`
	CreatedAt   time.Time `json:"created_at"`
}

func handleGetJobs(w http.ResponseWriter, r *http.Request) {
  // need to only select jobs from database that belong to company
  session, err := store.Get(r, "SESSION_KEY")
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }
  
  companyId, ok := session.Values["company_id"].(string)
  if !ok {
    http.Error(w, "unauthorized", http.StatusUnauthorized)
  }
  
  query := `SELECT id, job_name, company_name, user_id, company_id, created_at FROM jobs where company_id = $1`

  rows, err := db.Query(query, companyId)
  if err != nil {
    http.Error(w, "Failed to retrieve jobs", http.StatusInternalServerError)
    return
  }
  defer rows.Close()

  var jobs []Job

  for rows.Next() {
    var job Job
    if err := rows.Scan(&job.ID, &job.JobName, &job.CompanyName, &job.UserID, &job.CompanyID, &job.CreatedAt); err != nil {
      http.Error(w, "Failed to scan for jobs", http.StatusInternalServerError)
      return
    }
    jobs = append(jobs, job)
  }

  if err := rows.Err(); err != nil {
    http.Error(w, "Failed to retrieve jobs", http.StatusInternalServerError)
    return
  }

  w.Header().Set("Content-Type", "application/json")
  if err := json.NewEncoder(w).Encode(jobs); err != nil {
    http.Error(w, "Failed to encode jobs", http.StatusInternalServerError)
    return
  }
}

func handleGetMapWithJob(w http.ResponseWriter, r *http.Request) {
	err := templates.ExecuteTemplate(w, "index.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleGetMap(w http.ResponseWriter, r *http.Request) {
	err := templates.ExecuteTemplate(w, "index.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type loginSuccess struct {
	Success bool
	Error string
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
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

func renderLoginTemplateWithError(w http.ResponseWriter, errorMessage string) {
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


func handleGetContactPage(w http.ResponseWriter, r *http.Request) {
	err := templates.ExecuteTemplate(w, "contact.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleCreateJob(w http.ResponseWriter, r *http.Request) {
	jobName := r.FormValue("job-name")
	companyName := r.FormValue("company-name")

  err := createJobsTable()
  if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  id, err := insertJobIntoDb(jobName, companyName)
  if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  fmt.Println(id)

	http.Redirect(w, r, fmt.Sprintf("/map/%s", id), http.StatusSeeOther)
}

func insertJobIntoDb(jobName, companyName, userId, companyId string) (string, error) {
  query := `INSERT INTO jobs (id, job_name, company_name, user_id, company_id, created_at)
            VALUES (gen_random_uuid(), $1, $2, $3, $4, CURRENT_TIMESTAMP)
            RETURNING id
           `
  var id string
  err := db.QueryRow(query, jobName, companyName, userId, companyId).Scan(&id)
	//err := db.Exec(query, jobName, companyName).Scan(&id)
  if err != nil {
    log.Printf("Error inserting job into database: %v", err)
    return "", err
  }

  return id, nil
}

func createJobsTable() error {
	query := `CREATE TABLE IF NOT EXISTS jobs(
	            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	            job_name TEXT NOT NULL,
	            company_name TEXT NOT NULL, 
              user_id UUID NOT NULL,
              company_id UUID NOT NULL,
              created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
              FOREIGN KEY (user_id) REFERENCES users(id),
              FOREIGN KEY (company_id) REFERENCES companies(id)
	          );`

	_, err := db.Exec(query)
	if err != nil {
		log.Printf("Error create jobs table in database: %v", err)
    return err
	} else {
    return nil
  }
}

func createUsersTable() error {
	query := `CREATE TABLE users IF NOT EXISTS(
	            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
              company_id UUID NOT NULL,
	            email TEXT NOT NULL UNIQUE,
	            password TEXT NOT NULL, 
              access TEXT NOT NULL,
              created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
              FOREIGN KEY (company_id) REFERENCES companies(id)
	          );`

	_, err := db.Exec(query)
	if err != nil {
		log.Printf("Error create users table in database: %v", err)
    return err
	} else {
    return nil
  }
}

func createNewUser(email, password string) error {
  query := `INSERT INTO users (id, email, password, created_at)
            VALUES (gen_random_uuid(), $1, $2, CURRENT_TIMESTAMP)`
  _, err := db.Exec(query)
	if err != nil {
		log.Printf("Error inserting user into database: %v", err)
    return err
	}
  return nil
}
