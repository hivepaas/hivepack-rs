// Go's side of tools/tar-bench: one request a line on stdin, one answer a line
// on stdout, "<nanoseconds> <value>", or "error <message>". What is timed is
// reading or writing: what comes before it, as loading the archive into memory or
// making the headers, is left out.
//
// WHERE is where the archive is read from:
//
//	mem    from memory, through a plain io.Reader
//	buf    from a file, through bufio.Reader of 64 KiB
//	file   from a file, through a plain io.Reader, one read at a time
//	seek   from a file as it is, which archive/tar seeks past data with
//
// Requests:
//
//	list PATH WHERE
//	    Next on each entry, its data skipped. The value adds up the names'
//	    lengths and the sizes.
//	read PATH WHERE
//	    Next on each entry, and its data in reads of 64 KiB. The value is the
//	    bytes read.
//	many OUT KIND COUNT
//	    Writes an archive of COUNT entries of 16 bytes: KIND is ustar, pax (long
//	    names, and times in nanoseconds) or gnu (long names).
//	pack OUT LIST
//	    Writes a USTAR archive of LIST's lines of name, file, offset and length,
//	    by tabs.
//	writemany OUT KIND COUNT
//	writepack OUT LIST
//	    The same, timed: to a file through bufio.Writer of 64 KiB, or to nowhere
//	    if OUT is "-". The value is the bytes written.
//
// scripts/testdata.py builds it, with the toolchain go.mod names.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// A plain io.Reader, which archive/tar cannot seek.
type plain struct{ io.Reader }

func source(path, where string) (io.Reader, func(), error) {
	switch where {
	case "mem":
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		return plain{bytes.NewReader(data)}, func() {}, nil
	case "buf", "file", "seek":
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		done := func() { f.Close() }
		switch where {
		case "buf":
			return bufio.NewReaderSize(f, 1<<16), done, nil
		case "file":
			return plain{f}, done, nil
		}
		return f, done, nil
	}
	return nil, nil, fmt.Errorf("where: %s", where)
}

func list(path, where string) (time.Duration, uint64, error) {
	r, done, err := source(path, where)
	if err != nil {
		return 0, 0, err
	}
	defer done()
	tr := tar.NewReader(r)
	var value uint64
	start := time.Now()
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, 0, err
		}
		value += uint64(len(h.Name)) + uint64(h.Size)
	}
	return time.Since(start), value, nil
}

func read(path, where string) (time.Duration, uint64, error) {
	r, done, err := source(path, where)
	if err != nil {
		return 0, 0, err
	}
	defer done()
	tr := tar.NewReader(r)
	buf := make([]byte, 1<<16)
	var value uint64
	start := time.Now()
	for {
		_, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, 0, err
		}
		for {
			n, err := tr.Read(buf)
			value += uint64(n)
			if err == io.EOF {
				break
			}
			if err != nil {
				return 0, 0, err
			}
		}
	}
	return time.Since(start), value, nil
}

// An entry to write.
type item struct {
	h    tar.Header
	data []byte
}

func manyItems(kind string, count int) ([]item, error) {
	data := []byte("sixteen bytes...")
	mtime := time.Unix(1700000000, 0)
	long := strings.Repeat("a-long-folder-name/", 8)
	items := make([]item, count)
	for i := range items {
		name := fmt.Sprintf("dir%03d/sub%03d/file%06d.txt", i%100, i%997, i)
		h := tar.Header{Typeflag: tar.TypeReg, Name: name, Size: 16, Mode: 0o644, ModTime: mtime}
		switch kind {
		case "ustar":
			h.Format = tar.FormatUSTAR
		case "pax":
			h.Name = long + name
			h.ModTime = time.Unix(1700000000, int64(i)+1)
			h.Format = tar.FormatPAX
		case "gnu":
			h.Name = long + name
			h.Format = tar.FormatGNU
		default:
			return nil, fmt.Errorf("kind: %s", kind)
		}
		items[i] = item{h, data}
	}
	return items, nil
}

func packItems(listPath string) ([]item, error) {
	text, err := os.ReadFile(listPath)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	mtime := time.Unix(1700000000, 0)
	var items []item
	for _, line := range strings.Split(strings.TrimSpace(string(text)), "\n") {
		field := strings.Split(line, "\t")
		data, ok := files[field[1]]
		if !ok {
			if data, err = os.ReadFile(field[1]); err != nil {
				return nil, err
			}
			files[field[1]] = data
		}
		offset, _ := strconv.Atoi(field[2])
		length, _ := strconv.Atoi(field[3])
		h := tar.Header{Typeflag: tar.TypeReg, Name: field[0], Size: int64(length), Mode: 0o644, ModTime: mtime, Format: tar.FormatUSTAR}
		items = append(items, item{h, data[offset : offset+length]})
	}
	return items, nil
}

func writeItems(w io.Writer, items []item) error {
	tw := tar.NewWriter(w)
	for i := range items {
		if err := tw.WriteHeader(&items[i].h); err != nil {
			return err
		}
		if _, err := tw.Write(items[i].data); err != nil {
			return err
		}
	}
	return tw.Close()
}

// Writes the items to a file of 1 MiB buffers, to read back later.
func save(out string, items []item, err error) error {
	if err != nil {
		return err
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<20)
	if err := writeItems(w, items); err != nil {
		return err
	}
	return w.Flush()
}

// Counts what is written, and keeps none of it.
type nowhere struct{ n uint64 }

func (w *nowhere) Write(b []byte) (int, error) {
	w.n += uint64(len(b))
	return len(b), nil
}

// Writes the items, timed.
func timed(out string, items []item, err error) (time.Duration, uint64, error) {
	if err != nil {
		return 0, 0, err
	}
	if out == "-" {
		w := &nowhere{}
		start := time.Now()
		if err := writeItems(w, items); err != nil {
			return 0, 0, err
		}
		return time.Since(start), w.n, nil
	}
	f, err := os.Create(out)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<16)
	start := time.Now()
	if err := writeItems(w, items); err != nil {
		return 0, 0, err
	}
	if err := w.Flush(); err != nil {
		return 0, 0, err
	}
	d := time.Since(start)
	info, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	return d, uint64(info.Size()), nil
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		word := strings.Fields(in.Text())
		var (
			d     time.Duration
			value uint64
			err   error
		)
		switch {
		case len(word) == 3 && word[0] == "list":
			d, value, err = list(word[1], word[2])
		case len(word) == 3 && word[0] == "read":
			d, value, err = read(word[1], word[2])
		case len(word) == 4 && word[0] == "many":
			var count int
			if count, err = strconv.Atoi(word[3]); err == nil {
				items, e := manyItems(word[2], count)
				err = save(word[1], items, e)
			}
		case len(word) == 3 && word[0] == "pack":
			items, e := packItems(word[2])
			err = save(word[1], items, e)
		case len(word) == 4 && word[0] == "writemany":
			var count int
			if count, err = strconv.Atoi(word[3]); err == nil {
				items, e := manyItems(word[2], count)
				d, value, err = timed(word[1], items, e)
			}
		case len(word) == 3 && word[0] == "writepack":
			items, e := packItems(word[2])
			d, value, err = timed(word[1], items, e)
		default:
			err = fmt.Errorf("a bad request: %s", in.Text())
		}
		if err != nil {
			fmt.Printf("error %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%d %d\n", d.Nanoseconds(), value)
	}
}
