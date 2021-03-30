package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"html"
	"os"
	"regexp"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

const (
	file     = "./dump.xml"
	db_file  = "./tdb.sqlite"
	dump_len = 1300000000 // conservative estimate of the # of lines in the dump
)

var link_regex = regexp.MustCompile(`\[\[([^:]+?)\]\]`)
var title_regex = regexp.MustCompile(`<title>([^:]+?)<\/title>`)
var block_regex = regexp.MustCompile(`{{.+?}}`)
var redirect_regex = regexp.MustCompile(`<redirect title="([^:]+?)"`)

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
	file, _ := os.Open(file)
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
		file.Close()
	}()

	inside_page := true
	redirects_to := ""
	current_page := ""
	links := []string{}

	scanner := bufio.NewScanner(file)
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
				stmt.Exec(current_page, strings.Join(uniques(links), "\x01"), "")
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
			links = append(links, strings.Join(m, "|"))
		}
	}
}
