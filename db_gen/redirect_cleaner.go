package main

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

const (
	file     = "./dump.xml"
	db_file  = "./db.sqlite"
	tdb_file = "file:tdb.sqlite?mode=ro"
)

func main() {
	db, _ := sql.Open("sqlite3", db_file)
	tdb, _ := sql.Open("sqlite3", tdb_file)

	db.Exec("CREATE TABLE IF NOT EXISTS data (name TEXT PRIMARY KEY, links TEXT)")
	// gotta go fast
	db.Exec("PRAGMA locking_mode = EXCLUSIVE")
	db.Exec("BEGIN TRANSACTION")
	ins, _ := db.Prepare("INSERT OR REPLACE INTO data VALUES (?, ?)")

	redirects := make(map[string]string)

	redirect_entries, _ := tdb.Query("SELECT name, redirect FROM data WHERE redirect != \"\"")
	for redirect_entries.Next() {
		var k, v string
		redirect_entries.Scan(&k, &v)
		redirects[k] = v
	}

	fmt.Printf("finished reading db; found %d redirects\n\n", len(redirects))

	rows, _ := tdb.Query("SELECT * FROM data WHERE redirect = \"\"")
	for i := 0; rows.Next(); i++ {
		var name string
		var links_ string
		var redirect string
		rows.Scan(&name, &links_, &redirect)
		links := strings.Split(links_, "\x01")

		if i%10000 == 0 {
			db.Exec("END TRANSACTION")
			db.Exec("BEGIN TRANSACTION")
			fmt.Printf("\rprocessed %d rows", i)
		}

		for j, link := range links {
			parts := strings.Split(link, "|")
			if dest, r := redirects[parts[0]]; r {
				parts[0] = dest
			}
			links[j] = strings.Join(parts, "|")
		}
		ins.Exec(name, strings.Join(links, "\x01"))
	}

	rows.Close()
	ins.Close()
	db.Exec("END TRANSACTION")
	db.Exec("PRAGMA optimize")
	db.Close()
	tdb.Close()
}
