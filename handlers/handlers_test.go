package handlers

import (
    "bytes"
    "database/sql"
    "fmt"
    "os"
    "log"
    "mime/multipart"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "github.com/gorilla/mux"
    "github.com/joho/godotenv"
    "github.com/gorilla/sessions"
    _ "github.com/lib/pq" // PostgreSQL driver
)

// Helper function to create a multipart file
func createMultipartFile(fileName, content string) (*bytes.Buffer, string, error) {
    var buf bytes.Buffer
    writer := multipart.NewWriter(&buf)
    file, err := writer.CreateFormFile("file", fileName)
    if err != nil {
        return nil, "", err
    }
    _, err = file.Write([]byte(content))
    if err != nil {
        return nil, "", err
    }
    writer.Close()
    return &buf, writer.FormDataContentType(), nil
}

// Mocking a database function
func mockDB() (*sql.DB, func()) {
    // Initialize the in-memory database here or mock it if needed
    // Example uses PostgreSQL but might require a specific setup for testing
    err := godotenv.Load("../.env")
    if err != nil {
        log.Fatal("Error loading .env file")
    }
    dbUser := os.Getenv("DB_USER")
    fmt.Println(dbUser)
    dbPassword := os.Getenv("DB_PASSWORD")
    dbName := "test"
    dbHost := "localhost"
    dbPort := "5432"
    connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", dbUser, dbPassword, dbHost, dbPort, dbName)

    db, err := sql.Open("postgres", connStr)
    if err != nil {
        panic(fmt.Sprintf("Error opening database connection: %v", err))
    }

    // Setup the database schema or mock here if needed
    // Ensure to clean up after tests if using a real database
    return db, func() {
        db.Close() // Close the database connection after tests
    }
}

// TestHandleUploadLas tests the HandleUploadLas function
func TestHandleUploadLas(t *testing.T) {
    store := sessions.NewCookieStore([]byte("secret-key"))

    db, cleanup := mockDB()
    defer cleanup()

    // Mock or populate the database with test data
    jobId := "job456"
    adminId := "admin123"
    _, err := db.Exec(`INSERT INTO jobs (id, job_name, company_name, admin_id, created_at) VALUES ($1, 'Test Job', 'Test Company', $2, CURRENT_TIMESTAMP)`, jobId, adminId)
    if err != nil {
        t.Fatalf("Error inserting test data into database: %v", err)
    }

    // Set up the route and handler
    router := mux.NewRouter()
    router.HandleFunc("/upload/{id:[a-zA-Z0-9]+}", HandleUploadLas(store, db)).Methods("POST")

    // Test case: successful upload of a LAS file
    t.Run("successful upload", func(t *testing.T) {
        buf, contentType, err := createMultipartFile("test.las", "VERSION INFORMATION\nSome LAS file content here")
        if err != nil {
            t.Fatalf("Error creating multipart file: %v", err)
        }

        req := httptest.NewRequest("POST", fmt.Sprintf("/upload/%s", jobId), buf)
        req.Header.Add("Content-Type", contentType)

        recorder := httptest.NewRecorder()
        router.ServeHTTP(recorder, req)

        if status := recorder.Code; status != http.StatusOK {
            t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
        }

        expected := "LAS file uploaded and processed successfully"
        if recorder.Body.String() != expected {
            t.Errorf("Handler returned unexpected body: got %v want %v", recorder.Body.String(), expected)
        }
    })

    // Test case: upload of a non-LAS file
    t.Run("non-LAS file", func(t *testing.T) {
        buf, contentType, err := createMultipartFile("test.txt", "Some text content here")
        if err != nil {
            t.Fatalf("Error creating multipart file: %v", err)
        }

        req := httptest.NewRequest("POST", fmt.Sprintf("/upload/%s", jobId), buf)
        req.Header.Add("Content-Type", contentType)

        recorder := httptest.NewRecorder()
        router.ServeHTTP(recorder, req)

        if status := recorder.Code; status != http.StatusBadRequest {
            t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
        }

        expected := "File is not a LAS file"
        actual := strings.TrimSpace(recorder.Body.String())
        if actual != expected {
            t.Errorf("Handler returned unexpected body: got %q want %q", actual, expected)
        }
    })

    // Test case: file parsing error
    t.Run("file parsing error", func(t *testing.T) {
        var buf bytes.Buffer
        writer := multipart.NewWriter(&buf)
        writer.Close() // Correctly close the multipart writer

        req := httptest.NewRequest("POST", fmt.Sprintf("/upload/%s", jobId), &buf)
        req.Header.Add("Content-Type", writer.FormDataContentType())

        recorder := httptest.NewRecorder()
        router.ServeHTTP(recorder, req)

        if status := recorder.Code; status != http.StatusBadRequest {
            t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
        }

        expected := "Unable to get file"
        actual := strings.TrimSpace(recorder.Body.String())
        if actual != expected {
            t.Errorf("Handler returned unexpected body: got %q want %q", actual, expected)
        }
    })

    // Additional test case: database error
    t.Run("database error", func(t *testing.T) {
        faultyDB, _ := mockDB()
        faultyHandler := HandleUploadLas(store, faultyDB)

        buf, contentType, err := createMultipartFile("test.las", "Some LAS file content here")
        if err != nil {
            t.Fatalf("Error creating multipart file: %v", err)
        }

        req := httptest.NewRequest("POST", fmt.Sprintf("/upload/%s", jobId), buf)
        req.Header.Add("Content-Type", contentType)

        recorder := httptest.NewRecorder()
        faultyHandler.ServeHTTP(recorder, req)

        if status := recorder.Code; status != http.StatusInternalServerError {
            t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusInternalServerError)
        }

        expected := "Error getting admin id from jobs"
        actual := strings.TrimSpace(recorder.Body.String())
        if actual != expected {
            t.Errorf("Handler returned unexpected body: got %q want %q", actual, expected)
        }
    })
}

