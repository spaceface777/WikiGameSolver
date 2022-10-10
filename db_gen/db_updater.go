package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/alecthomas/units"
	"github.com/aybabtme/iocontrol"
)

const (
	MiB = 1 << 20
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
					f()
					fmt.Println()
					ticker.Stop()
					return
				}
			}
		}
	}()
	return stop
}

var pages []struct {
	Title []byte
	Links []int32
}

func main() {
	read_db()
	write_db()
}

func read_db() {
	f := iocontrol.NewMeasuredReader(bufio.NewReader(os.Stdin))

	stop := set_interval(300*time.Millisecond, func() {
		read := units.Base2Bytes(int64(f.Total())).Floor().String()
		rate := units.Base2Bytes(f.BytesPerSec()).Floor().String()
		fmt.Fprintf(os.Stderr, "\rStep 1/2: reading old database.     %s/s, %s total   \r", rate, read)
	})

	var nr_pages int32
	if err := binary.Read(f, binary.LittleEndian, &nr_pages); err != nil {
		panic(err)
	}
	pages = make([]struct {
		Title []byte
		Links []int32
	}, nr_pages)

	for i := int32(0); i < nr_pages; i++ {
		var nr_links uint16
		page := &pages[i]
		if err := binary.Read(f, binary.LittleEndian, &nr_links); err != nil {
			panic(err)
		}
		page.Links = make([]int32, nr_links)
	}
	for i := int32(0); i < nr_pages; i++ {
		page := &pages[i]
		for j := range page.Links {
			if err := binary.Read(f, binary.LittleEndian, &page.Links[j]); err != nil {
				panic(err)
			}
		}
	}
	for i := int32(0); i < nr_pages; i++ {
		page := &pages[i]
		var title_len uint16
		if err := binary.Read(f, binary.LittleEndian, &title_len); err != nil {
			panic(err)
		}
		page.Title = make([]byte, title_len)
	}
	for i := int32(0); i < nr_pages; i++ {
		page := &pages[i]
		if _, err := io.ReadFull(f, page.Title); err != nil {
			panic(err)
		}
	}

	stop <- true
}

func write_db() {
	f := iocontrol.NewMeasuredWriter(bufio.NewWriter(os.Stdout))

	stop := set_interval(300*time.Millisecond, func() {
		read := units.Base2Bytes(int64(f.Total())).Floor().String()
		rate := units.Base2Bytes(f.BytesPerSec()).Floor().String()
		fmt.Fprintf(os.Stderr, "\rStep 2/2: writing new database.     %s/s, %s total   \r", rate, read)
	})

	if err := binary.Write(f, binary.LittleEndian, int32(len(pages))); err != nil {
		panic(err)
	}
	for _, page := range pages {
		if err := binary.Write(f, binary.LittleEndian, uint16(len(page.Links))); err != nil {
			panic(err)
		}
	}
	for _, page := range pages {
		for _, link := range page.Links {
			if err := binary.Write(f, binary.LittleEndian, int32(link)); err != nil {
				panic(err)
			}
		}
	}
	for _, page := range pages {
		if err := binary.Write(f, binary.LittleEndian, uint16(len(page.Title))); err != nil {
			panic(err)
		}
	}
	for _, page := range pages {
		if _, err := f.Write([]byte(page.Title)); err != nil {
			panic(err)
		}
	}

	stop <- true
}
