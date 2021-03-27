import os
import sqlite
import term
import time

struct App {
mut:
	db sqlite.DB
	// used for dfs optimizations, to avoid dupe searches
	depths map[string]int
}

fn main() {
	mut app := &App{
		db: sqlite.connect('db.sqlite') or { panic(err) }
	}
	os.input('') // not sure why this is needed, but it prevents an issue
	mut start_time := time.new_stopwatch({})
	for {
		start := os.input('\nenter a starting Wikipedia entry: ')
		end := os.input('enter a final Wikipedia entry: ')
		start_time.restart()
		path := app.find_path(start, end) or {
			eprintln(term.red('error: $err'))
			continue
		}
		println('found a path:')
		for i, node in path {
			println(' ${i + 1}. $node')
		}
		elapsed := f64(start_time.elapsed().milliseconds()) / 1000
		println('took ${elapsed:0.2} seconds')
	}
}

fn (mut app App) get(db_entry string) []string {
	// clean_entry := db_entry.replace_each()
	res := app.db.exec_one('SELECT links FROM data WHERE name = "$db_entry"') or { return [] }
	return res.vals[0].split('\x01')
}

// this is an optimized iddfs / bfs hybrid,
// that is significantly faster / more efficient than a dfs
// and also uses much less memory than a bfs
fn (mut app App) find_path(start string, target string) ?[]string {
	if app.get(start).len == 0 {
		return error('start page `$start` not in the database')
	}
	if app.get(target).len == 0 {
		return error('end page `$start` not in the database')
	}
	for depth := 1; ; depth++ {
		if path := app.dfs(start, target, 0, depth, []) {
			return path
		}
	}

	// unreachable, but we've gotta make the compiler happy
	return []
}

// TODO: threading
// TODO: make this non-recursive?
// i guess C compilers might add a TCO optimization in `-prod` mode, so that may be unnecessary
fn (mut app App) dfs(node string, target string, depth int, limit int, path_ []string) ?[]string {
	if node == target {
		mut path := path_.clone()
		path << node
		return path
	}

	if depth > limit {
		app.depths[node] = depth
		return none
	}

	if app.depths[node] >= limit - depth {
		return none
	}

	if limit > depth + 1 {
		children := app.get(node)
		mut path := path_.clone()
		path << node
		for child in children {
			if found := app.dfs(child, target, depth + 1, limit, path) {
				return found
			}
		}
	}

	app.depths[node] = limit - depth
	return none
}
