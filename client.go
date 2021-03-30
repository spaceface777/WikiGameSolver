package main

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"net/http"
	_ "net/http/pprof"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var cache map[string]int = make(map[string]int)
var stmt *sql.Stmt

func main() {
	open_db()

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	if len(os.Args) < 3 {
		// interactive mode
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("Enter starting entry: ")
			start, _ := reader.ReadString('\n')
			start = strings.Trim(start, "\r\n\t\v ")

			fmt.Print("Enter target entry: ")
			target, _ := reader.ReadString('\n')
			target = strings.Trim(target, "\r\n\t\v ")

			run(start, target)
		}
	} else {
		//
		start, target := os.Args[1], os.Args[2]
		run(start, target)
	}

	db.Exec("PRAGMA optimize")
}

func open_db() {
	db_, err := sql.Open("sqlite3", "db.sqlite")
	if err != nil {
		log.Fatalf("Error opening database: %q\n", err)
	}
	db = db_
	// fast queries
	db.Exec("PRAGMA locking_mode = EXCLUSIVE")
	db.Exec("PRAGMA synchronous = OFF")
	db.Exec("PRAGMA journal_mode = OFF")
	db.Exec("PRAGMA temp_store = OFF")
	db.Exec(fmt.Sprintf("PRAGMA threads = %d", runtime.NumCPU()))
	stmt_, err := db.Prepare("SELECT links FROM data WHERE name = ?")
	if err != nil {
		log.Fatalf("Error preparing stmt: %q\n", err)
	}
	stmt = stmt_
}

func get(entry string) []string {
	var data string
	if err := stmt.QueryRow(entry).Scan(&data); err != nil {
		return []string{}
	}
	return strings.Split(data, "\x01")
}

func run(start string, target string) {
	start_time := time.Now()

	path, err := find_path(start, target)
	if err != nil {
		fmt.Printf("Error finding path: %q\n", err)
		return
	}
	for i, node := range path {
		fmt.Printf(" %d. %s\n", i+1, node)
	}

	end_time := time.Since(start_time)
	fmt.Printf("Search took %s\n\n", end_time)
}

func find_path(start string, target string) ([]string, error) {
	// defer func() {
	// 	cache = make(map[string]int)
	// 	runtime.GC()
	// }()

	if len(get(start)) == 0 {
		return nil, errors.New(fmt.Sprintf("start page `%s` not found", start))
	}
	if len(get(target)) == 0 {
		return nil, errors.New(fmt.Sprintf("target page `%s` not found", target))
	}
	for depth := 2; ; depth++ {
		path := dfs(start, target, 0, depth, []string{})
		if len(path) > 0 {
			return path, nil
		}
		fmt.Println("Increasing depth...")
	}
}

// TODO: threaded / non-recursive implementation?
func dfs(node string, target string, depth int, limit int, path_ []string) []string {
	if node == target {
		path := append([]string(nil), path_...)
		path = append(path, node)
		return path
	}

	if depth > limit || cache[node] >= limit-depth {
		return []string{}
	}

	if limit > depth+1 {
		children := get(node)
		path := append([]string(nil), path_...)
		path = append(path, node)

		for _, child := range children {
			child = strings.Split(child, "|")[0]
			res := dfs(child, target, depth+1, limit, path)
			if len(res) > 0 {
				return res
			}
		}
	}

	cache[node] = limit - depth
	return []string{}
}
