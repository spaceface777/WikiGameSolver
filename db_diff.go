package main

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

const (
	odb_file = "file:db_old.sqlite?mode=ro"
	ndb_file = "file:db.sqlite?mode=ro"
)

func main() {
	odb, _ := sql.Open("sqlite3", odb_file)
	ndb, _ := sql.Open("sqlite3", ndb_file)
	defer odb.Close()
	defer ndb.Close()

	// gotta go fast
	for _, x := range []*sql.DB{odb, ndb} {
		x.Exec("PRAGMA locking_mode = EXCLUSIVE")
		x.Exec("BEGIN TRANSACTION")
	}

	rows, _ := odb.Query("SELECT * FROM data")
	for i := 0; rows.Next(); i++ {
		var name, olinks_, nlinks_ string
		rows.Scan(&name, &olinks_)
		ndb.QueryRow("SELECT links FROM data WHERE name = ?", name).Scan(&nlinks_)

		olinks := strings.Split(olinks_, "\x01")
		nlinks := strings.Split(nlinks_, "\x01")

		fmt.Printf("%#v -> %#v\n", olinks, nlinks)
		fmt.Printf("%d -> %d\n", len(olinks), len(nlinks))
	}
}
