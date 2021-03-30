package main

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"net/http"
	_ "net/http/pprof"

	"github.com/mattn/go-sqlite3"
	flag "github.com/spf13/pflag"
)

var db *sql.DB
var cache map[string]int = make(map[string]int)
var stmt *sql.Stmt

var start string = ""
var target string = ""
var mem bool = false

func init() {
	flag.StringVarP(&start, "start", "s", "", "starting Wikipedia entry")
	flag.StringVarP(&target, "target", "t", "", "target Wikipedia entry")
	flag.BoolVarP(&mem, "memory", "m", false, "load the entire database to memory")

	help := false
	flag.BoolVarP(&help, "help", "h", false, "show this help menu")
	flag.Parse()

	if help {
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Printf("Usage: %s [option]...\n", filepath.Base(os.Args[0]))
	fmt.Println("Find the shortest path between two Wikipedia entries,")
	fmt.Println("by clicking on the embedded links inside each page")
	fmt.Println("\nAvailable CLI options:")
	flag.PrintDefaults()
}

func main() {
	open_db()

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	if start == "" {
		// interactive mode
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("Enter starting entry: ")
			start, _ = reader.ReadString('\n')
			start = strings.Trim(start, "\r\n\t\v ")

			fmt.Print("Enter target entry: ")
			target, _ = reader.ReadString('\n')
			target = strings.Trim(target, "\r\n\t\v ")
		}
	} else if target == "" {
		fmt.Println("Error: no target page specified\n")
		printHelp()
		os.Exit(1)
	}
	run(start, target)
	db.Exec("PRAGMA optimize")
}

func open_db() {
	if mem {
		var conns [2]*sqlite3.SQLiteConn
		i := 0
		sql.Register("sqlite3_with_hook_example",
			&sqlite3.SQLiteDriver{
				ConnectHook: func(conn_ *sqlite3.SQLiteConn) error {
					// fmt.Printf("Connected: %#v\n", conn_)
					conns[i] = conn_
					i++
					return nil
				}})

		idb, err := sql.Open("sqlite3_with_hook_example", "db.sqlite")
		if err != nil {
			log.Fatalf("Error opening database: %q\n", err)
		}
		idb.Ping() // force connect

		db_, err := sql.Open("sqlite3_with_hook_example", ":memory:")
		if err != nil {
			log.Fatalf("Error opening database: %q\n", err)
		}
		db = db_
		db.Ping() // force connect
		if _, err = db.Exec("CREATE TABLE data (name TEXT PRIMARY KEY, links TEXT)"); err != nil {
			log.Fatal(err)
		}

		bk, err := conns[1].Backup("main", conns[0], "main")
		if _, err = bk.Step(1000000); err != nil {
			log.Fatal(err)
		}
		bk.Finish()
	} else {
		db_, err := sql.Open("sqlite3", "db.sqlite")
		if err != nil {
			log.Fatalf("Error opening database: %q\n", err)
		}
		db = db_
	}
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

	if depth > limit || (!mem && cache[node] >= limit-depth) {
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

	if !mem {
		cache[node] = limit - depth
	}
	return []string{}
}
