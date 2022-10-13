package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
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

var dump_date uint32

var title_to_old_id = make(map[string]int, 0)
var old_id_to_title = make(map[int]string, 0)
var old_id_to_new_id = make(map[int]int, 0)
var redirects = make(map[int]int, 0)

var titles []string
var old_ids []int
var links [][]int

func title_to_new_id(title string) (int, bool) {
	id := sort.SearchStrings(titles, title)
	if id < len(titles) && titles[id] == title {
		return id, true
	}
	return id, false
}

func main() {
	for _, lang := range os.Args[1:] {
		language = lang
		fmt.Fprintf(os.Stderr, "Generating database for %s\n\n", language+"wiki")
		get_dump_urls()
		build_page_table()
		build_redirects()

		old_ids = nil
		old_id_to_title = nil
		title_to_old_id = nil
		runtime.GC()

		links = make([][]int, len(titles))
		build_links()

		redirects = make(map[int]int, 0)
		old_id_to_new_id = make(map[int]int, 0)
		runtime.GC()

		write_db()

		titles = make([]string, 0, 1<<20)
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
	for name, file := range redirecttable.Files {
		t, _ := strconv.Atoi(strings.Split(name, "-")[1])
		dump_date = uint32(t) - 20000000
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

	stop := set_interval(200*time.Millisecond, func() {
		nread := int64(m.Total())
		nrate := m.BytesPerSec()
		read := units.Base2Bytes(nread).Floor().String()
		rate := units.Base2Bytes(nrate).Floor().String()

		rem := time.Duration(float64(ContentLength-nread) / float64(nrate) * float64(time.Second))
		percent := float64(nread) / float64(ContentLength) * 100
		if rem < time.Minute {
			fmt.Fprintf(os.Stderr, "\rStep 1/4     %s/s - %.0f%%, %s of %s, %d sec. left               \r", rate, percent, read, total, int(rem.Seconds()))
		} else {
			fmt.Fprintf(os.Stderr, "\rStep 1/4     %s/s - %.0f%%, %s of %s, %d min. left               \r", rate, percent, read, total, int(rem.Minutes()))
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
				old_id_to_title[id] = title
				title_to_old_id[title] = id
			}
		}
	}

	stop <- true
}

func build_redirects() {
	redirects_old := make(map[int]int, 0)

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

	stop := set_interval(100*time.Millisecond, func() {
		nread := int64(m.Total())
		nrate := m.BytesPerSec()
		read := units.Base2Bytes(nread).Floor().String()
		rate := units.Base2Bytes(nrate).Floor().String()

		percent := float64(nread) / float64(ContentLength) * 100
		rem := time.Duration(float64(ContentLength-nread) / float64(nrate) * float64(time.Second))
		if rem < time.Minute {
			fmt.Fprintf(os.Stderr, "\rStep 2/4     %s/s - %.0f%%, %s of %s, %d sec. left               \r", rate, percent, read, total, int(rem.Seconds()))
		} else {
			fmt.Fprintf(os.Stderr, "\rStep 2/4     %s/s - %.0f%%, %s of %s, %d min. left               \r", rate, percent, read, total, int(rem.Minutes()))
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

			if _, ok := old_id_to_title[source_id]; !ok {
				continue
			}
			if target_id, ok := title_to_old_id[title]; ok {
				redirects_old[source_id] = target_id
			}
		}
	}

	for old_source_id, old_target_id := range redirects_old {
		initial_id := old_source_id
		nr_redirects := 0
		for _, ok := redirects_old[old_target_id]; ok; {
			old_target_id = redirects_old[old_target_id]
			nr_redirects++
			if old_target_id == initial_id || nr_redirects > 100 {
				old_target_id = -1
				break
			}
		}
		if old_target_id != -1 {
			redirects_old[old_source_id] = old_target_id
		} else {
			delete(redirects_old, old_source_id)
		}
	}

	titles = make([]string, len(title_to_old_id))
	old_ids = make([]int, len(title_to_old_id))
	i := 0
	for title, old_id := range title_to_old_id {
		titles[i] = title
		old_ids[i] = old_id
		i++
	}
	sort.Sort(Sorter{})
	for new_id, old_id := range old_ids {
		old_id_to_new_id[old_id] = new_id
	}

	for old_source_id, old_target_id := range redirects_old {
		redirects[old_source_id] = old_id_to_new_id[old_target_id]
	}

	stop <- true
}

type Sorter struct{}

func (s Sorter) Len() int {
	return len(titles)
}

func (s Sorter) Less(i, j int) bool {
	return titles[i] < titles[j]
}

func (s Sorter) Swap(i, j int) {
	titles[i], titles[j] = titles[j], titles[i]
	old_ids[i], old_ids[j] = old_ids[j], old_ids[i]
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

	stop := set_interval(300*time.Millisecond, func() {
		nread := int64(m.Total())
		nrate := m.BytesPerSec()
		read := units.Base2Bytes(nread).Floor().String()
		rate := units.Base2Bytes(nrate).Floor().String()

		percent := float64(nread) / float64(ContentLength) * 100
		rem := time.Duration(float64(ContentLength-nread) / float64(nrate) * float64(time.Second))
		if rem < time.Minute {
			fmt.Fprintf(os.Stderr, "\rStep 3/4     %s/s - %.0f%%, %s of %s, %d sec. left               \r", rate, percent, read, total, int(rem.Seconds()))
		} else {
			fmt.Fprintf(os.Stderr, "\rStep 3/4     %s/s - %.0f%%, %s of %s, %d min. left               \r", rate, percent, read, total, int(rem.Minutes()))
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

			if redirect_id, ok := redirects[source_id]; ok {
				source_id = redirect_id
			} else if new_id, ok := old_id_to_new_id[source_id]; ok {
				source_id = new_id
			} else {
				continue
			}
			if target_id, ok := title_to_new_id(title); ok && source_id != target_id {
				links[source_id] = append(links[source_id], target_id)
			}
		}
	}

	for i := range titles {
		sort.Ints(links[i])
	}

	stop <- true
}

const format_ver = 1

func write_db() {
	var f *os.File
	if isatty.IsTerminal(os.Stdout.Fd()) {
		file, err := os.Create("./" + language + ".bin")
		if err != nil {
			panic(err)
		}
		f = file
	} else {
		f = os.Stdout
	}

	bw := bufio.NewWriterSize(f, 1*MiB)
	w := iocontrol.NewMeasuredWriter(bw)

	stop := set_interval(100*time.Millisecond, func() {
		read := units.Base2Bytes(int64(w.Total())).Floor().String()
		rate := units.Base2Bytes(w.BytesPerSec()).Floor().String()
		fmt.Fprintf(os.Stderr, "\rStep 4/4     %s/s, %s total   \r", rate, read)
	})

	if _, err := w.Write([]byte("WIKI")); err != nil {
		panic(err)
	}

	version := dump_date<<8 | format_ver
	if err := binary.Write(w, binary.LittleEndian, version); err != nil {
		panic(err)
	}

	if err := binary.Write(w, binary.LittleEndian, int32(len(titles))); err != nil {
		panic(err)
	}
	for i, links := range links {
		if len(links) >= 1<<16 {
			err := fmt.Errorf("\n\ntoo many links: page #%d=`%s`: %d", i, titles[i], len(links))
			panic(err)
		}
		if err := binary.Write(w, binary.LittleEndian, uint16(len(links))); err != nil {
			panic(err)
		}
	}
	for _, links := range links {
		for _, link := range links {
			if err := binary.Write(w, binary.LittleEndian, int32(link)); err != nil {
				panic(err)
			}
		}
	}
	for _, title := range titles {
		if err := binary.Write(w, binary.LittleEndian, uint16(len(title))); err != nil {
			panic(err)
		}
	}
	for _, title := range titles {
		if _, err := w.Write([]byte(title)); err != nil {
			panic(err)
		}
	}

	stop <- true
	bw.Flush()
	f.Sync()
	f.Close()
}
