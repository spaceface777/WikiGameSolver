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
	mut start, mut target := if os.args.len == 1 {
		os.input('\nenter a starting Wikipedia entry: '),
		os.input('enter a target Wikipedia entry: ')
	} else {
		os.args[1],
		os.args[2]
	}
	mut start_time := time.new_stopwatch({})
	path := app.find_path(start, target) or {
		eprintln(term.red('error: $err'))
		return
	}
	println('found a path:')
	for i, node in path {
		println(' ${i + 1}. $node')
	}
	elapsed := f64(start_time.elapsed().milliseconds()) / 1000
	println('\ntook ${elapsed:.2f} seconds')
}

fn (mut app App) get(db_entry string) []string {
	// clean_entry := db_entry.replace_each()
	res := app.db.exec_one('SELECT links FROM data WHERE name = "$db_entry"') or { return [] }
	first := res.vals[0]
	split := first.split('\x01')
	return split
}

// this is an optimized iddfs / bfs hybrid,
// that is significantly faster / more efficient than a dfs
// and also uses much less memory than a bfs
fn (mut app App) find_path(start string, target string) ?[]string {
	if app.get(start).len == 0 {
		return error('start page `$start` not in the database')
	}
	if app.get(target).len == 0 {
		return error('target page `$target` not in the database')
	}
	for depth := 1; ; depth++ {
		path := app.dfs(start, target, 0, depth, [])
		if path.len > 0 {
			return path
		}
	}

	// unreachable, but we've gotta make the compiler happy
	return []
}

// TODO: threading
// TODO: make this non-recursive?
// i guess C compilers might add a TCO optimization in `-prod` mode, so that may be unnecessary
fn (mut app App) dfs(node string, target string, depth int, limit int, path_ []string) []string {
	if node == target {
		mut path := path_.clone()
		path << node
		return path
	}

	if depth > limit {
		app.depths[node] = depth
		return []
	}

	if app.depths[node] >= limit - depth {
		return []
	}

	if limit > depth + 1 {
		children := app.get(node)
		mut path := path_.clone()
		path << node
		for child in children {
			res := app.dfs(child, target, depth + 1, limit, path)
			if res.len > 0 {
				return res
			}
		}
	}

	app.depths[node] = limit - depth
	return []
}
