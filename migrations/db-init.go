package migrations

import (
  "database/sql"
  "io/ioutil"
  "log"
)

func ExecuteSQLFile(db *sql.DB, filePath string) error {
  content, err := ioutil.ReadFile(filePath)
  if err != nil {
    return err
  }

  _, err = db.Exec(string(content))
  if err != nil {
    log.Printf("Error executing sql file: %v", err)
    return err
  }
  return nil
}

func RunMigrations(db *sql.DB) error {
  if err := ExecuteSQLFile(db, "./migrations/schemas.sql"); err != nil {
    return err
  }
  return nil
}
