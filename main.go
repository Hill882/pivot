package main

import (
    //"flag"
    "log"
    "html/template"
    "path/filepath"
    "net/http"
    "os"
    "fmt"
    "github.com/joho/godotenv"
    _ "github.com/lib/pq"
    "database/sql"
    "golang.org/x/crypto/bcrypt"
    "github.com/gorilla/sessions"
    "github.com/gorilla/mux"
)

var db *sql.DB
var templates *template.Template
var store *sessions.CookieStore

func main() {
  r := mux.NewRouter()
    //listenAddr := flag.String("listenaddr", ":8080", "Address to listen on")
    //flag.Parse()

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
    r.HandleFunc("/login", handleLogin).Methods("GET", "POST")
    r.HandleFunc("/logout", handleLogout).Methods("GET")
    r.HandleFunc("/contact", handleGetContactPage).Methods("GET")
	
    // protected routes
    // GET
    r.Handle("/map", authenticationMiddleware(store, http.HandlerFunc(handleGetMap))).Methods("GET")
    r.Handle("/map/{id}", authenticationMiddleware(store, http.HandlerFunc(handleGetMapWithJob))).Methods("GET")
    r.Handle("/createJob", authenticationMiddleware(store, http.HandlerFunc(handleCreateJob))).Methods("POST")

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

    //fmt.Printf("Starting server on http://localhost%s/login\n", *listenAddr)
    //log.Fatal(http.ListenAndServe(*listenAddr, nil))
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
		
		var storedPassword string
		err = db.QueryRow("SELECT password FROM users WHERE email = $1", email).Scan(&storedPassword)
		if err != nil {
      if err == sql.ErrNoRows {
        renderLoginTemplateWithError(w, "Incorrect email or password")
      } else {
        http.Error(w, "Database error", http.StatusInternalServerError)
      }
      return
		}

    if password != storedPassword {
      renderLoginTemplateWithError(w, "Incorrect password")
      return
    }

    // IN PRODUCTION
		//if !checkPasswordHash(password, storedPassword) {
		//	fmt.Println("Invalid password")
		//	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		//	return
		//}
    
    // create a new session
    session, err := store.Get(r, "SESSION_KEY")
    if err != nil {
      log.Fatal("ERROR HERE")
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }

    //set session values
    session.Values["authenticated"] = true
    session.Values["user"] = email

    err = session.Save(r, w)
    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }

    http.Redirect(w, r, "/map", http.StatusSeeOther)
	}
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
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

func insertJobIntoDb(jobName, companyName string) (string, error) {
  query := `INSERT INTO jobs (id, job_name, company_name, created_at)
            VALUES (gen_random_uuid(), $1, $2, CURRENT_TIMESTAMP)
            RETURNING id
           `
  var id string
  err := db.QueryRow(query, jobName, companyName).Scan(&id)
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
              created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
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
	            email TEXT NOT NULL UNIQUE,
	            password TEXT NOT NULL, 
              created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
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
