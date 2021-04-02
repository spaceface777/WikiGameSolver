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
	"runtime/debug"

	//"runtime"
	"strings"
	"time"

	"net/http"
	_ "net/http/pprof"

	// lru "github.com/hashicorp/golang-lru"
	_ "github.com/mattn/go-sqlite3"
	flag "github.com/spf13/pflag"
)

var start = ""
var target = ""
var mem = false
var verbose = false
var cache_size = 0

func init() {
	debug.SetGCPercent(100)

	flag.StringVarP(&start, "start", "s", "", "starting Wikipedia entry")
	flag.StringVarP(&target, "target", "t", "", "target Wikipedia entry")
	flag.BoolVarP(&mem, "memory", "m", false, "load the entire database to memory")
	flag.BoolVarP(&verbose, "verbose", "v", false, "print verbose output")
	flag.IntVarP(&cache_size, "cache_size", "c", 1000000, "custom cache size. Expect ~200mb of memory usage for every million entries")

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

var db *sql.DB

// var cache *lru.ARCCache
var stmt *sql.Stmt

func main() {
	// cache, _ = lru.NewARC(cache_size)

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
			run(start, target)
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
		// TODO: figure out why the backup API doesn't work
		fmt.Println("Reading db into memory...")
		fdb, err := sql.Open("sqlite3", "dbv3_lite.sqlite")
		if err != nil {
			log.Fatalf("Error opening database: %q\n", err)
		}
		mdb, err := sql.Open("sqlite3", ":memory:")
		if err != nil {
			log.Fatalf("Error opening database: %q\n", err)
		}

		mdb.Exec("CREATE TABLE IF NOT EXISTS data (name TEXT PRIMARY KEY, links TEXT)")
		mdb.Exec("BEGIN TRANSACTION")

		ins, err := mdb.Prepare("INSERT OR REPLACE INTO data VALUES (?, ?)")
		if err != nil {
			log.Fatalf("Error preparing stmt: %q\n", err)
		}

		var count int
		if x := fdb.QueryRow("SELECT COUNT(*) FROM data"); x != nil {
			x.Scan(&count)
		}

		rows, err := fdb.Query("SELECT * FROM data")
		if err != nil {
			log.Fatal(err)
		}
		for i := 0; rows.Next(); i++ {
			var name string
			var links string
			rows.Scan(&name, &links)

			if i%10000 == 0 {
				mdb.Exec("END TRANSACTION")
				mdb.Exec("BEGIN TRANSACTION")
				fmt.Printf("\rprocessed %d rows (%.2f%%)", i, float64(i*100)/float64(count))
				// we need to free as much memory as possible
				runtime.GC()
			}

			ins.Exec(name, links)
		}

		mdb.Exec("END TRANSACTION")
		fmt.Println("\rFinished reading db into memory\n\n")

		db = mdb

	} else {
		db_, err := sql.Open("sqlite3", "dbv3.sqlite")
		if err != nil {
			log.Fatalf("Error opening database: %q\n", err)
		}
		db = db_
	}
	// fast queries
	//db.Exec("PRAGMA locking_mode = EXCLUSIVE")
	//db.Exec("PRAGMA synchronous = OFF")
	//db.Exec("PRAGMA journal_mode = OFF")
	//db.Exec("PRAGMA temp_store = OFF")
	//db.Exec(fmt.Sprintf("PRAGMA threads = %d", runtime.NumCPU()))
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
	defer func() {
		// cache.Purge()
		runtime.GC()
	}()

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
func dfs(node_ string, target string, depth int, limit int, path_ []string) []string {
	// s := strings.Split(node_, "|")
	// node := s[0]
	// fnode := node
	// if len(s) > 1 {
	// 	fnode = s[1] + " (" + s[0] + ")"
	// 	// fnode = fmt.Sprintf("%s (%s)", s[1], s[0])
	// }
	node, fnode := node_, node_

	if node == target {
		path := append([]string(nil), path_...)
		path = append(path, fnode)
		return path
	}

	if depth > limit {
		return []string{}
	}

	// if val, ok := cache.Get(node); ok && val.(int) >= limit-depth {
	// 	return []string{}
	// }

	if limit > depth+1 {
		children := get(node)
		path := append([]string(nil), path_...)
		path = append(path, fnode)

		for _, child := range children {
			res := dfs(child, target, depth+1, limit, path)
			if len(res) > 0 {
				return res
			}
		}
	}

	// cache.Add(node, limit-depth)
	return []string{}
}
