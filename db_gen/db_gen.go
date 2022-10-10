package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/units"
	"github.com/aybabtme/iocontrol"
	"github.com/klauspost/pgzip"
	"github.com/mattn/go-isatty"
)

const (
	mirror     = "https://chuangtzu.ftp.acc.umu.se/mirror/wikimedia.org/dumps"
	dump_index = mirror + "/index.json"

	MiB = 1 << 20
)

var (
	language      string
	pages_url     string
	pagelinks_url string
	redirects_url string
)

func set_interval(interval time.Duration, f func()) chan bool {
	ticker := time.NewTicker(interval)
	stop := make(chan bool)
	go func() {
		for {
			select {
			case <-ticker.C:
				f()
			case s := <-stop:
				if s {
					fmt.Fprintln(os.Stderr)
					ticker.Stop()
					return
				}
			}
		}
	}()
	return stop
}

type DumpIndex struct {
	Wikis map[string]struct {
		Jobs map[string]struct {
			Status string `json:"status"`
			Files  map[string]struct {
				URL string `json:"url"`
			} `json:"files"`
		} `json:"jobs"`
	} `json:"wikis"`
}

var id_to_title = make(map[int]string, 0)
var title_to_id = make(map[string]int, 0)
var redirects = make(map[int]int, 0)
var links = make(map[int][]int, 0)

func main() {
	for _, lang := range os.Args[1:] {
		language = lang
		fmt.Fprintf(os.Stderr, "Generating database for %s", language+"wiki")
		get_dump_urls()
		build_page_table()
		build_redirects()
		build_links()

		redirects = nil

		write_db()

		id_to_title = nil
		title_to_id = nil
		links = nil
	}
}

func get_dump_urls() {
	res, err := http.Get(dump_index)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	var index DumpIndex
	if err := json.NewDecoder(res.Body).Decode(&index); err != nil {
		panic(err)
	}

	jobs := index.Wikis[language+"wiki"].Jobs

	redirecttable := jobs["redirecttable"]
	if redirecttable.Status != "done" || len(redirecttable.Files) != 1 {
		panic("dump is incomplete")
	}
	for _, file := range redirecttable.Files {
		redirects_url = mirror + file.URL
	}

	pagelinkstable := jobs["pagelinkstable"]
	if pagelinkstable.Status != "done" || len(pagelinkstable.Files) != 1 {
		panic("dump is incomplete")
	}
	for _, file := range pagelinkstable.Files {
		pagelinks_url = mirror + file.URL
	}

	pagetable := jobs["pagetable"]
	if pagetable.Status != "done" || len(pagetable.Files) != 1 {
		panic("dump is incomplete")
	}
	for _, file := range pagetable.Files {
		pages_url = mirror + file.URL
	}
}

func build_page_table() {
	res, err := http.Get(pages_url)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	ContentLength := res.ContentLength
	total := units.Base2Bytes(ContentLength).Floor().String()

	m := iocontrol.NewMeasuredReader(res.Body)

	r, err := pgzip.NewReader(m)
	if err != nil {
		panic(err)
	}
	defer r.Close()

	stop := set_interval(500*time.Millisecond, func() {
		nread := int64(m.Total())
		nrate := m.BytesPerSec()
		read := units.Base2Bytes(nread).Floor().String()
		rate := units.Base2Bytes(nrate).Floor().String()

		rem := time.Duration(float64(ContentLength-nread) / float64(nrate) * float64(time.Second))
		if rem < time.Minute {
			fmt.Fprintf(os.Stderr, "\rStep 1/3     %s/s - %s of %s, %d sec. left               \r", rate, read, total, int(rem.Seconds()))
		} else {
			fmt.Fprintf(os.Stderr, "\rStep 1/3     %s/s - %s of %s, %d min. left               \r", rate, read, total, int(rem.Minutes()))
		}
	})

	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, 100*MiB)
	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, "INSERT INTO `page`") {
			continue
		}

		line = line[27 : len(line)-2]

		pre := ""
		for _, insert := range strings.Split(line, "),(") {
			if pre != "" {
				insert = pre + insert
				pre = ""
			}
			var id int
			var ns int
			var title string
			var is_redirect bool

			s := 0
			n := 0
			in_quote := false

			for i, c := range insert {
				if c == '\'' {
					j := i - 1
					escaped := true
					for insert[j] == '\\' {
						escaped = !escaped
						j--
					}
					if !escaped {
						continue
					}
					in_quote = !in_quote
				}
				if c == ',' && !in_quote {
					j := i - 1
					escaped := true
					for insert[j] == '\\' {
						escaped = !escaped
						j--
					}
					if !escaped {
						continue
					}
					if n == 0 {
						id, _ = strconv.Atoi(insert[s:i])
					} else if n == 1 {
						ns, _ = strconv.Atoi(insert[s:i])
					} else if n == 2 {
						title = insert[s+1 : i-1]
						title = strings.Replace(title, "\\\\", "\\", -1)
						title = strings.Replace(title, "\\'", "'", -1)
						title = strings.Replace(title, "\\\"", "\"", -1)
						title = strings.Replace(title, "_", " ", -1)
						title = strings.TrimSpace(title)
					} else if n == 4 {
						is_redirect = insert[s:i] == "1"
					}
					n++
					s = i + 1
				}
			}
			if n < 11 {
				pre = insert
				continue
			} else if n > 11 {
				fmt.Fprintln(os.Stderr)
				fmt.Fprintln(os.Stderr, "PARSING ERROR in part 1")
				fmt.Fprintln(os.Stderr, n)
				fmt.Fprintln(os.Stderr, insert)
				fmt.Fprintln(os.Stderr, title)
				fmt.Fprintln(os.Stderr)
			}

			if ns != 0 {
				continue
			}

			if !is_redirect {
				id_to_title[id] = title
				title_to_id[title] = id
			}
		}
	}

	stop <- true
}

func build_redirects() {
	res, err := http.Get(redirects_url)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	ContentLength := res.ContentLength
	total := units.Base2Bytes(ContentLength).Floor().String()

	m := iocontrol.NewMeasuredReader(res.Body)

	r, err := pgzip.NewReader(m)
	if err != nil {
		panic(err)
	}
	defer r.Close()

	stop := set_interval(500*time.Millisecond, func() {
		nread := int64(m.Total())
		nrate := m.BytesPerSec()
		read := units.Base2Bytes(nread).Floor().String()
		rate := units.Base2Bytes(nrate).Floor().String()

		rem := time.Duration(float64(ContentLength-nread) / float64(nrate) * float64(time.Second))
		if rem < time.Minute {
			fmt.Fprintf(os.Stderr, "\rStep 2/3     %s/s - %s of %s, %d sec. left               \r", rate, read, total, int(rem.Seconds()))
		} else {
			fmt.Fprintf(os.Stderr, "\rStep 2/3     %s/s - %s of %s, %d min. left               \r", rate, read, total, int(rem.Minutes()))
		}
	})

	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, 100*MiB)
	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, "INSERT INTO `redirect`") {
			continue
		}

		line = line[31 : len(line)-2]

		pre := ""
		for _, insert := range strings.Split(line, "),(") {
			if pre != "" {
				insert = pre + insert
				pre = ""
			}
			var source_id int
			var ns int
			var title string

			s := 0
			n := 0
			in_quote := false

			for i, c := range insert {
				if c == '\'' {
					j := i - 1
					escaped := true
					for insert[j] == '\\' {
						escaped = !escaped
						j--
					}
					if !escaped {
						continue
					}
					in_quote = !in_quote
				}
				if c == ',' && !in_quote {
					j := i - 1
					escaped := true
					for insert[j] == '\\' {
						escaped = !escaped
						j--
					}
					if !escaped {
						continue
					}
					if n == 0 {
						source_id, _ = strconv.Atoi(insert[s:i])
					} else if n == 1 {
						ns, _ = strconv.Atoi(insert[s:i])
					} else if n == 2 {
						title = insert[s+1 : i-1]
						title = strings.Replace(title, "\\\\", "\\", -1)
						title = strings.Replace(title, "\\'", "'", -1)
						title = strings.Replace(title, "\\\"", "\"", -1)
						title = strings.Replace(title, "_", " ", -1)
						title = strings.TrimSpace(title)
					}
					n++
					s = i + 1
				}
			}
			if n < 4 {
				pre = insert
				continue
			} else if n > 4 {
				fmt.Fprintln(os.Stderr)
				fmt.Fprintln(os.Stderr, "PARSING ERROR in part 2")
				fmt.Fprintln(os.Stderr, n)
				fmt.Fprintln(os.Stderr, insert)
				fmt.Fprintln(os.Stderr, title)
				fmt.Fprintln(os.Stderr)
				os.Exit(1)
			}

			if ns != 0 {
				continue
			}

			if _, ok := id_to_title[source_id]; !ok {
				continue
			}
			if target_id, ok := title_to_id[title]; ok {
				redirects[source_id] = target_id
			}
		}
	}

	for source_id, target_id := range redirects {
		initial_id := source_id
		nr_redirects := 0
		for _, ok := redirects[target_id]; ok; {
			target_id = redirects[target_id]
			nr_redirects++
			if target_id == initial_id || nr_redirects > 100 {
				target_id = -1
				break
			}
		}
		if target_id != -1 {
			redirects[source_id] = target_id
		} else {
			delete(redirects, source_id)
		}
	}
	stop <- true
}

func build_links() {
	res, err := http.Get(pagelinks_url)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	ContentLength := res.ContentLength
	total := units.Base2Bytes(ContentLength).Floor().String()

	m := iocontrol.NewMeasuredReader(res.Body)

	r, err := pgzip.NewReader(m)
	if err != nil {
		panic(err)
	}
	defer r.Close()

	stop := set_interval(500*time.Millisecond, func() {
		nread := int64(m.Total())
		nrate := m.BytesPerSec()
		read := units.Base2Bytes(nread).Floor().String()
		rate := units.Base2Bytes(nrate).Floor().String()

		rem := time.Duration(float64(ContentLength-nread) / float64(nrate) * float64(time.Second))
		if rem < time.Minute {
			fmt.Fprintf(os.Stderr, "\rStep 3/3     %s/s - %s of %s, %d sec. left               \r", rate, read, total, int(rem.Seconds()))
		} else {
			fmt.Fprintf(os.Stderr, "\rStep 3/3     %s/s - %s of %s, %d min. left               \r", rate, read, total, int(rem.Minutes()))
		}
	})

	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, 100*MiB)
	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, "INSERT INTO `pagelinks`") {
			continue
		}

		line = line[32 : len(line)-2]

		pre := ""
		for _, insert := range strings.Split(line, "),(") {
			if pre != "" {
				insert = pre + insert
				pre = ""
			}
			var source_id int
			var ns int
			var title string
			var source_ns int

			s := 0
			n := 0
			in_quote := false

			for i, c := range insert {
				if c == '\'' {
					j := i - 1
					escaped := true
					for insert[j] == '\\' {
						escaped = !escaped
						j--
					}
					if !escaped {
						continue
					}
					in_quote = !in_quote
				}
				if c == ',' && !in_quote {
					j := i - 1
					escaped := true
					for insert[j] == '\\' {
						escaped = !escaped
						j--
					}
					if !escaped {
						continue
					}

					if n == 0 {
						source_id, _ = strconv.Atoi(insert[s:i])
					} else if n == 1 {
						ns, _ = strconv.Atoi(insert[s:i])
					} else if n == 2 {
						title = insert[s+1 : i-1]
						title = strings.Replace(title, "\\\\", "\\", -1)
						title = strings.Replace(title, "\\'", "'", -1)
						title = strings.Replace(title, "\\\"", "\"", -1)
						title = strings.Replace(title, "_", " ", -1)
						title = strings.TrimSpace(title)
					} else if n == 3 {
						source_ns, _ = strconv.Atoi(insert[s:i])
					}
					n++
					s = i + 1
				}
			}
			if n < 3 {
				pre = insert
				continue
			} else if n > 3 {
				fmt.Fprintln(os.Stderr)
				fmt.Fprintln(os.Stderr, "PARSING ERROR in part 3")
				fmt.Fprintln(os.Stderr, n)
				fmt.Fprintln(os.Stderr, insert)
				fmt.Fprintln(os.Stderr, title)
				fmt.Fprintln(os.Stderr)
				os.Exit(1)
			}

			if ns != 0 || source_ns != 0 {
				continue
			}

			if _, ok := id_to_title[source_id]; !ok {
				continue
			}
			if redirect_id, ok := redirects[source_id]; ok {
				source_id = redirect_id
			}
			if target_id, ok := title_to_id[title]; ok && source_id != target_id {
				links[source_id] = append(links[source_id], target_id)
			}
		}
	}

	stop <- true
}

func write_db() {
	fmt.Fprintln(os.Stderr, "\nWriting database...")

	var f io.Writer
	if isatty.IsTerminal(os.Stdout.Fd()) {
		file, err := os.Open("./" + language + ".bin")
		if err != nil {
			panic(err)
		}
		defer file.Close()
		f = bufio.NewWriter(file)
	} else {
		f = bufio.NewWriter(os.Stdout)
	}

	titles := make([]string, 0, len(id_to_title))
	for _, title := range id_to_title {
		titles = append(titles, title)
	}
	sort.Strings(titles)

	sorted_links := make([][]int, 0, len(id_to_title))
	for _, title := range titles {
		l := links[title_to_id[title]]
		for i := 0; i < len(l); i++ {
			l[i] = sort.SearchStrings(titles, id_to_title[l[i]])
		}
		sort.Ints(l)

		sorted_links = append(sorted_links, l)
	}

	if err := binary.Write(f, binary.LittleEndian, int32(len(titles))); err != nil {
		panic(err)
	}
	for i, links := range sorted_links {
		if len(links) >= 1<<16 {
			panic("too many links: " + titles[i] + " (" + strconv.Itoa(i) + "/" + strconv.Itoa(title_to_id[titles[i]]) + "): " + strconv.Itoa(len(links)))
		}
		if err := binary.Write(f, binary.LittleEndian, uint16(len(links))); err != nil {
			panic(err)
		}
	}
	for _, links := range sorted_links {
		for _, link := range links {
			if err := binary.Write(f, binary.LittleEndian, int32(link)); err != nil {
				panic(err)
			}
		}
	}
	for _, title := range titles {
		if err := binary.Write(f, binary.LittleEndian, uint16(len(title))); err != nil {
			panic(err)
		}
	}
	for _, title := range titles {
		if _, err := f.Write([]byte(title)); err != nil {
			panic(err)
		}
	}
}
