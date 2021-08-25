package main

import (
	"bufio"
	"compress/bzip2"
	"database/sql"
	"fmt"
	"html"
	"net/http"
	"os"
	"regexp"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

const (
	db_tmpl  = "TEMP_[LANG].db"
	url_tmpl = "http://dumps.wikimedia.your.org/[LANG]wiki/latest/[LANG]wiki-latest-pages-articles.xml.bz2"
	dump_len = 1300000000 // conservative estimate of the # of lines in the dump
)

var link_regex = regexp.MustCompile(`\[\[([^:]+?)\]\]`)
var title_regex = regexp.MustCompile(`<title>([^:]+?)<\/title>`)
var block_regex = regexp.MustCompile(`{{.+?}}`)
var redirect_regex = regexp.MustCompile(`<redirect title="([^:]+?)"`)

func main() {
	for _, country := range os.Args[1:] {
		db_file := strings.Replace(db_tmpl, "[LANG]", country, -1)
		dump_url := strings.Replace(url_tmpl, "[LANG]", country, -1)
		db, _ := sql.Open("sqlite3", db_file)

		db.Exec("CREATE TABLE IF NOT EXISTS data (name TEXT PRIMARY KEY, links TEXT, redirect TEXT)")
		// gotta go fast
		db.Exec("PRAGMA locking_mode = EXCLUSIVE")
		db.Exec("BEGIN TRANSACTION")

		stmt, _ := db.Prepare("INSERT OR REPLACE INTO data VALUES (?, ?, ?)")

		defer func() {
			stmt.Close()
			db.Exec("END TRANSACTION")
			db.Close()
		}()

		inside_page := true
		redirects_to := ""
		current_page := ""
		links := []string{}

		client := http.Client{}
		res, _ := client.Get(dump_url)
		defer res.Body.Close()

		unc := bzip2.NewReader(res.Body)	
		scanner := bufio.NewScanner(unc)
		scanner.Buffer(nil, 1024*1024*100)

		for i := 0; scanner.Scan(); i++ {
			line := strings.Trim(scanner.Text(), "\r\n\t\v ")

			if i%1000000 == 0 {
				db.Exec("END TRANSACTION")
				db.Exec("BEGIN TRANSACTION")
				fmt.Printf("\rprocessed: %d (~%.2f%%)", i, float64(i*100)/float64(dump_len))
			}

			if !inside_page {
				if line == "<page>" {
					inside_page = true
				}
				continue
			}

			if title := title_regex.FindAllStringSubmatch(line, -1); len(title) > 0 && len(title[0]) > 1 {
				current_page = title[0][1]
				continue
			}

			if redirect := redirect_regex.FindStringSubmatch(line); len(redirect) > 0 {
				redirects_to = redirect[1]
				continue
			}

			if line == "</page>" {
				if redirects_to == "" {
					stmt.Exec(current_page, strings.Join(links, "\x01"), "")
				} else {
					stmt.Exec(current_page, "", redirects_to)
				}
				inside_page = false
				links = []string{}
				redirects_to = ""
				continue
			}

			line = block_regex.ReplaceAllLiteralString(line, "")
			for _, match := range link_regex.FindAllStringSubmatch(line, -1) {
				m := strings.Split(html.UnescapeString(match[1]), "|")
				// m := strings.Split(match[1], "|")
				m[0] = strings.Split(m[0], "#")[0]
				links = append(links, m[0])
			}
		}
	}
}
