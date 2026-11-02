// age's side of tools/age-bench: one request a line on stdin, one answer a line on
// stdout, "<nanoseconds> <value>", or "error <message>". Files are read into memory
// first, outside the time.
//
//	keys DIR
//	    Writes DIR/x25519.key, an age key; DIR/pq.key, a post-quantum one;
//	    DIR/ssh.key, an OpenSSH Ed25519 key;
//	    DIR/many.keys, a file of 1,000 age keys; and DIR/many.pub, their
//	    recipients.
//	make OUT INPUT KIND
//	    Encrypts the file INPUT to OUT. KIND is x25519, x25519-ten (nine other
//	    recipients first), pq, ssh, scrypt14, scrypt18 (age's default) or armored
//	    (x25519, in ASCII armor).
//	decrypt PATH KIND DIR COUNT
//	    Decrypts the file COUNT times, reading all of it. The value is the bytes
//	    read. KIND is as for make.
//	encrypt INPUT KIND DIR COUNT
//	    Encrypts the file COUNT times, 64 KiB at a time, to a writer that only counts. The value is the bytes written. KIND is as
//	    for make.
//	parse PATH
//	    age.ParseIdentities. The value is the number of keys.
//	recipients PATH
//	    age.ParseRecipients. The value is the number of keys.
//	keygen COUNT
//	    age.GenerateX25519Identity COUNT times. The value is COUNT.
//
// scripts/testdata.py builds it; go.sum pins what it is built from.
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"golang.org/x/crypto/ssh"
)

const passphrase = "correct-horse-battery-staple"

func keys(dir string) error {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "x25519.key"), []byte(id.String()+"\n"), 0o600); err != nil {
		return err
	}
	pq, err := age.GenerateHybridIdentity()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "pq.key"), []byte(pq.String()+"\n"), 0o600); err != nil {
		return err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ssh.key"), pem.EncodeToMemory(block), 0o600); err != nil {
		return err
	}
	var many, pub bytes.Buffer
	for i := 0; i < 1000; i++ {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return err
		}
		many.WriteString("# a key\n" + id.String() + "\n")
		pub.WriteString("# a key\n" + id.Recipient().String() + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "many.pub"), pub.Bytes(), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "many.keys"), many.Bytes(), 0o600)
}

func x25519Identity(dir string) (*age.X25519Identity, error) {
	text, err := os.ReadFile(filepath.Join(dir, "x25519.key"))
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Identity(strings.TrimSpace(string(text)))
}

func pqIdentity(dir string) (*age.HybridIdentity, error) {
	text, err := os.ReadFile(filepath.Join(dir, "pq.key"))
	if err != nil {
		return nil, err
	}
	return age.ParseHybridIdentity(strings.TrimSpace(string(text)))
}

func identity(kind, dir string) (age.Identity, error) {
	switch kind {
	case "x25519", "x25519-ten", "armored":
		return x25519Identity(dir)
	case "pq":
		return pqIdentity(dir)
	case "ssh":
		text, err := os.ReadFile(filepath.Join(dir, "ssh.key"))
		if err != nil {
			return nil, err
		}
		return agessh.ParseIdentity(text)
	case "scrypt14", "scrypt18":
		return age.NewScryptIdentity(passphrase)
	}
	return nil, fmt.Errorf("kind: %s", kind)
}

func recipients(kind, dir string) ([]age.Recipient, error) {
	switch kind {
	case "x25519", "armored":
		id, err := x25519Identity(dir)
		if err != nil {
			return nil, err
		}
		return []age.Recipient{id.Recipient()}, nil
	case "pq":
		id, err := pqIdentity(dir)
		if err != nil {
			return nil, err
		}
		return []age.Recipient{id.Recipient()}, nil
	case "x25519-ten":
		id, err := x25519Identity(dir)
		if err != nil {
			return nil, err
		}
		var list []age.Recipient
		for i := 0; i < 9; i++ {
			other, err := age.GenerateX25519Identity()
			if err != nil {
				return nil, err
			}
			list = append(list, other.Recipient())
		}
		return append(list, id.Recipient()), nil
	case "ssh":
		text, err := os.ReadFile(filepath.Join(dir, "ssh.key"))
		if err != nil {
			return nil, err
		}
		key, err := ssh.ParsePrivateKey(text)
		if err != nil {
			return nil, err
		}
		r, err := agessh.ParseRecipient(string(ssh.MarshalAuthorizedKey(key.PublicKey())))
		if err != nil {
			return nil, err
		}
		return []age.Recipient{r}, nil
	case "scrypt14", "scrypt18":
		r, err := age.NewScryptRecipient(passphrase)
		if err != nil {
			return nil, err
		}
		if kind == "scrypt14" {
			r.SetWorkFactor(14)
		} else {
			r.SetWorkFactor(18)
		}
		return []age.Recipient{r}, nil
	}
	return nil, fmt.Errorf("kind: %s", kind)
}

func makeFile(out, input, kind, dir string) error {
	list, err := recipients(kind, dir)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	var w io.Writer = f
	var armored io.WriteCloser
	if kind == "armored" {
		armored = armor.NewWriter(f)
		w = armored
	}
	wc, err := age.Encrypt(w, list...)
	if err != nil {
		return err
	}
	if _, err := wc.Write(data); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	if armored != nil {
		return armored.Close()
	}
	return nil
}

func decrypt(path, kind, dir string, count int) (time.Duration, uint64, error) {
	id, err := identity(kind, dir)
	if err != nil {
		return 0, 0, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	var value uint64
	buf := make([]byte, 1<<16)
	start := time.Now()
	for i := 0; i < count; i++ {
		// age --decrypt reads through a bufio.Reader, and looks for armor.
		var src io.Reader = bufio.NewReader(bytes.NewReader(data))
		if kind == "armored" {
			src = armor.NewReader(src)
		}
		r, err := age.Decrypt(src, id)
		if err != nil {
			return 0, 0, err
		}
		for {
			n, err := r.Read(buf)
			value += uint64(n)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return 0, 0, err
			}
		}
	}
	return time.Since(start), value, nil
}

// counter is a writer that only counts.
type counter struct{ n uint64 }

func (c *counter) Write(p []byte) (int, error) {
	c.n += uint64(len(p))
	return len(p), nil
}

func encrypt(input, kind, dir string, count int) (time.Duration, uint64, error) {
	list, err := recipients(kind, dir)
	if err != nil {
		return 0, 0, err
	}
	data, err := os.ReadFile(input)
	if err != nil {
		return 0, 0, err
	}
	sink := &counter{}
	start := time.Now()
	for i := 0; i < count; i++ {
		var w io.Writer = sink
		var armored io.WriteCloser
		if kind == "armored" {
			armored = armor.NewWriter(sink)
			w = armored
		}
		wc, err := age.Encrypt(w, list...)
		if err != nil {
			return 0, 0, err
		}
		for rest := data; len(rest) > 0; {
			n := min(len(rest), 1<<16)
			if _, err := wc.Write(rest[:n]); err != nil {
				return 0, 0, err
			}
			rest = rest[n:]
		}
		if err := wc.Close(); err != nil {
			return 0, 0, err
		}
		if armored != nil {
			if err := armored.Close(); err != nil {
				return 0, 0, err
			}
		}
	}
	return time.Since(start), sink.n, nil
}

func parseRecipients(path string) (time.Duration, uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	start := time.Now()
	list, err := age.ParseRecipients(bytes.NewReader(data))
	if err != nil {
		return 0, 0, err
	}
	return time.Since(start), uint64(len(list)), nil
}

func keygen(count int) (time.Duration, uint64, error) {
	start := time.Now()
	for i := 0; i < count; i++ {
		if _, err := age.GenerateX25519Identity(); err != nil {
			return 0, 0, err
		}
	}
	return time.Since(start), uint64(count), nil
}

func parse(path string) (time.Duration, uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	start := time.Now()
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return 0, 0, err
	}
	return time.Since(start), uint64(len(ids)), nil
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	dir := ""
	for in.Scan() {
		word := strings.Fields(in.Text())
		var (
			d     time.Duration
			value uint64
			err   error
		)
		switch {
		case len(word) == 2 && word[0] == "keys":
			dir = word[1]
			err = keys(dir)
		case len(word) == 4 && word[0] == "make":
			err = makeFile(word[1], word[2], word[3], dir)
		case len(word) == 5 && word[0] == "decrypt":
			var count int
			if count, err = strconv.Atoi(word[4]); err == nil {
				d, value, err = decrypt(word[1], word[2], word[3], count)
			}
		case len(word) == 5 && word[0] == "encrypt":
			var count int
			if count, err = strconv.Atoi(word[4]); err == nil {
				d, value, err = encrypt(word[1], word[2], word[3], count)
			}
		case len(word) == 2 && word[0] == "parse":
			d, value, err = parse(word[1])
		case len(word) == 2 && word[0] == "recipients":
			d, value, err = parseRecipients(word[1])
		case len(word) == 2 && word[0] == "keygen":
			var count int
			if count, err = strconv.Atoi(word[1]); err == nil {
				d, value, err = keygen(count)
			}
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
