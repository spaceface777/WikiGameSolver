package main

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

const (
	db_file  = "./[LANG].db"
	tdb_file = "file:TEMP_[LANG].db?mode=ro"
)

func uniques(s []string) []string {
	seen := make(map[string]struct{}, len(s))
	j := 0
	for _, v := range s {
		part := v
		idx := strings.IndexByte(v, '|')
		if idx > 0 {
			part = v[:idx]
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		s[j] = v
		j++
	}
	return s[:j]
}

func main() {
	for _, lang := os.Args[1..] {
		db, _ := sql.Open("sqlite3", strings.Replace(db_file, "[LANG]", lang))
		tdb, _ := sql.Open("sqlite3", strings.Replace(tdb_file, "[LANG]", lang))

		fmt.Println("caching db into memory...")
		db.Exec("CREATE TABLE IF NOT EXISTS data (name TEXT PRIMARY KEY, links TEXT)")
		// gotta go fast
		db.Exec("PRAGMA locking_mode = EXCLUSIVE")
		db.Exec("BEGIN TRANSACTION")
		ins, _ := db.Prepare("INSERT OR REPLACE INTO data VALUES (?, ?)")

		var row_count int
		if x := tdb.QueryRow("SELECT COUNT(*) FROM data"); x != nil {
			x.Scan(&row_count)
		}

		redirects := make(map[string]string)
		redirect_entries, _ := tdb.Query("SELECT name, redirect FROM data WHERE redirect != \"\"")
		for redirect_entries.Next() {
			var k, v string
			redirect_entries.Scan(&k, &v)
			redirects[k] = v
		}

		x := float64(row_count - len(redirects))
		fmt.Println("finished caching db into memory")

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
				fmt.Printf("\rprocessed %d rows (%.2f%%)", i, float64(i*100)/x)
			}

			for j, link := range links {
				parts := strings.Split(link, "|")
				if dest, found := redirects[parts[0]]; found {
					parts[0] = dest
				}
				links[j] = strings.Join(parts, "|")
			}
			ins.Exec(name, strings.Join(uniques(links), "\x01"))
			// ins.Exec(name, strings.Join(links, "\x01"))
		}

		rows.Close()
		ins.Close()
		db.Exec("END TRANSACTION")
		db.Exec("PRAGMA optimize")
		db.Close()
		tdb.Close()
	}
}
