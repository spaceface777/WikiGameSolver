(async () => /* TLA */ {

const readline = require('readline')
const fs = require('fs')

const sqlite = require('sqlite3')
const db_file = '../db.sqlite'
const db = new sqlite.Database(db_file)

db.exec('CREATE TABLE IF NOT EXISTS data (name TEXT PRIMARY KEY, links TEXT)')

const file = 'enwiki-20210101-pages-articles-multistream.xml'
const dump_len = 1300000000 // conservative estimate, used for providing progress info

const link_regex = /\[\[([^:]+?)(?:\|(.+?))?\]\]/g
const title_regex = /<title>([^:]+?)<\/title>/i
const block_regex = /{{.+?}}/gi

let inside_page = false
let current_page = ''
let links = []
let i = 0

const log = (...args) => console.log(args.length ? `[${new Date().toLocaleTimeString()}]` : '', ...args)

// gotta go fast
db.exec('PRAGMA synchronous = OFF')
db.exec('PRAGMA journal_mode = OFF')
db.exec('BEGIN TRANSACTION')

// writing to disk in batches is much more efficient than 
let last_size = 0
const start_time = Date.now() / 1000 | 0
const interval = setInterval(() => {
    db.run('END TRANSACTION', () => {
        let size = fs.statSync(db_file).size
        log(`\x1b[2J\x1b[H`)
        log(`processed: ${i} (~${(i * 100 / dump_len).toFixed(2)}%)`)
        log(`new size: ${(size / (1024 * 1024 * 1024)).toFixed(2)} gb`)
        log(`speed: ${((size - last_size) / (1024 * 1024)).toFixed(2)} mb/s (avg: ${(size / (((Date.now() / 1000 | 0) - start_time) * 1024 * 1024)).toFixed(2)} mb/s)`)
        log(`mem: ${(process.memoryUsage().heapTotal / 1024 / 1024).toFixed(1)} mb`)
        db.run('BEGIN TRANSACTION')
        last_size = size        
    })
}, 1000)

const rl = readline.createInterface(fs.createReadStream(file, { encoding: 'utf8' }))
for await (let line of rl) {
    i++

    line = line.trim()

    if (!inside_page) {
        if (line == '<page>') {
            inside_page = true
        }
        continue
    } else {
        const title = line.match(title_regex)
        if (title) {
            let new_page = title[1] ?? ''
            db.run('INSERT OR REPLACE INTO data VALUES (?, ?)', current_page, links.join('\x01'))
            current_page = new_page
            links = []
            continue
        }
    }

    if (line == '</page>') {
        inside_page = false
        continue
    }

    line = line.replace(block_regex, '')
    for (const link_ of line.matchAll(link_regex)) {
        links.push(link_[1])
    }
}

clearInterval(interval)
db.close();

})()
