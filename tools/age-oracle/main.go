// The Go side of hivepack's comparison tests for age.
//
// It reads one request per line on stdin and answers each on one line of
// stdout, with the code age v1.3.2 runs: age itself (filippo.io/age), and
// its primitives from Go's standard library and golang.org/x/crypto
// v0.55.0, the release age v1.3.2 requires.
// The Rust tests ask the port the same questions and compare the answers as
// text. scripts/testdata.py builds it with the Go toolchain; go.sum pins
// what it is built from.
//
// Byte strings are hexadecimal, and "-" is an empty one.
//
//	sha256 <data>
//	sha512 <data>
//	    Answered "ok <digest>".
//
//	blake2s <key> <data>
//	    BLAKE2s-256 (x/crypto/blake2s), for hivepack::crypto and not age's:
//	    "ok <digest>", or "err" for a key over 32 bytes.
//
//	hmac256 <key> <data>
//	hmac512 <key> <data>
//	    HMAC-SHA256 or HMAC-SHA512. Answered "ok <mac>".
//
//	pbkdf2 <iterations> <length> <password> <salt>
//	    PBKDF2-HMAC-SHA256 (crypto/pbkdf2). Answered "ok <key>".
//
//	hkdf <salt> <ikm> <info> <length>
//	    HKDF-SHA256 as age uses it (x/crypto/hkdf), <salt> "none" for none.
//	    Answered "ok <key>", or "err" past 255 × 32 bytes.
//
//	chacha20 <key> <nonce> <counter> <data>
//	    <data> XORed with ChaCha20 (x/crypto/chacha20) from block
//	    <counter>. Answered "ok <data>".
//
//	seal <key> <nonce> <aad> <data>
//	    ChaCha20-Poly1305 (x/crypto/chacha20poly1305). Answered
//	    "ok <ciphertext and tag>".
//
//	open <key> <nonce> <aad> <ciphertext and tag>
//	    Answered "ok <plaintext>", or "err" if the tag does not match.
//
//	x25519 <scalar> <point>
//	    X25519 (x/crypto/curve25519). Answered "ok <point>", or "err" for an
//	    all-zero result, which x/crypto refuses.
//
//	scrypt <log2 N> <r> <p> <length> <password> <salt>
//	    x/crypto/scrypt. Answered "ok <key>", or "err" for parameters it
//	    refuses.
//
//	sshkey <seed> <passphrase>
//	    The Ed25519 key of the 32-byte <seed>, as an OpenSSH private key
//	    file, encrypted with <passphrase> unless it is "-" (ssh-keygen's
//	    defaults: bcrypt with 16 rounds, aes256-ctr). Answered
//	    "ok <key file> <authorized_keys line>".
//
//	encrypt <recipients> <armor> <plaintext>
//	    An age file of <plaintext>, to <recipients>: a comma-separated list
//	    of age1... public keys and "s:<authorized_keys line>" SSH keys, or
//	    one "p:<passphrase>:<work factor>". Armored if <armor> is 1.
//	    Answered "ok <file>".
//
//	encryptwith <random> <recipients> <armor> <plaintext>
//	    The same, with crypto/rand reading <random>, so that the file is one
//	    the port can write byte for byte. Answered "ok <file> <bytes of
//	    <random> read>", or "err" if a recipient does not parse or age refuses
//	    the recipients.
//
//	    In <recipients>, also "R:<file>", a recipients file read as age -R
//	    reads it (cmd/age's parseRecipientsFile), and "i:<file>:<passphrase>",
//	    what encrypts to an identity file as age -i does when encrypting.
//
//	keygen <random>
//	    A new X25519 identity with crypto/rand reading <random>. Answered
//	    "ok <the identity's String> <the recipient's String>".
//
//	keygenpq <random>
//	    A new post-quantum identity with crypto/rand reading <random>. Answered
//	    "ok <the identity's String> <the recipient's String>".
//
//	recipientpq <text>
//	    <text> as age.ParseHybridRecipient reads it. Answered "ok <what its
//	    String gives>", or "err".
//
//	recipient <text>
//	    <text> as age.ParseX25519Recipient reads it. Answered "ok <what its
//	    String gives>", or "err".
//
//	decrypt <identities> <file>
//	    <file> decrypted as age --decrypt reads it (cmd/age's decrypt: the
//	    armor found from the first line, PowerShell's mangling refused),
//	    with <identities>: a comma-separated list of AGE-SECRET-KEY-1...
//	    keys, "p:<passphrase>:<max work factor>", and
//	    "f:<file>:<passphrase>", an identity file read as age -i reads it
//	    (cmd/age's parseIdentitiesFile: a file of keys, an age file of
//	    them, or an SSH key), whose passphrase prompts all answer
//	    <passphrase>, or fail if it is "-". Answered
//	    "<outcome> <length> <sha256> <prompts>", the outcome as age's
//	    testkit_test.go tells it ("success", "header", "no-match", "hmac",
//	    "armor" or "payload", or "identity" if an identity file did not
//	    parse), with the length and SHA-256 of all the plaintext given out,
//	    even when the payload fails later, and how many times a passphrase
//	    was asked for.
package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"

	"crypto/ed25519"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh"
)

func unhex(s string) []byte {
	if s == "-" {
		return []byte{}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func ok(b []byte) string {
	if len(b) == 0 {
		return "ok -"
	}
	return "ok " + hex.EncodeToString(b)
}

func number(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}

func digest(h hash.Hash, data []byte) string {
	h.Write(data)
	return ok(h.Sum(nil))
}

func answer(words []string) string {
	switch {
	case words[0] == "sha256" && len(words) == 2:
		return digest(sha256.New(), unhex(words[1]))
	case words[0] == "sha512" && len(words) == 2:
		return digest(sha512.New(), unhex(words[1]))
	case words[0] == "blake2s" && len(words) == 3:
		h, err := blake2s.New256(unhex(words[1]))
		if err != nil {
			return "err"
		}
		return digest(h, unhex(words[2]))
	case words[0] == "hmac256" && len(words) == 3:
		return digest(hmac.New(sha256.New, unhex(words[1])), unhex(words[2]))
	case words[0] == "hmac512" && len(words) == 3:
		return digest(hmac.New(sha512.New, unhex(words[1])), unhex(words[2]))
	case words[0] == "pbkdf2" && len(words) == 5:
		key, err := pbkdf2.Key(sha256.New, string(unhex(words[3])), unhex(words[4]),
			number(words[1]), number(words[2]))
		if err != nil {
			return "err"
		}
		return ok(key)
	case words[0] == "hkdf" && len(words) == 5:
		var salt []byte
		if words[1] != "none" {
			salt = unhex(words[1])
		}
		out := make([]byte, number(words[4]))
		h := hkdf.New(sha256.New, unhex(words[2]), salt, unhex(words[3]))
		if _, err := io.ReadFull(h, out); err != nil {
			return "err"
		}
		return ok(out)
	case words[0] == "chacha20" && len(words) == 5:
		c, err := chacha20.NewUnauthenticatedCipher(unhex(words[1]), unhex(words[2]))
		if err != nil {
			return "bad"
		}
		c.SetCounter(uint32(number(words[3])))
		data := unhex(words[4])
		c.XORKeyStream(data, data)
		return ok(data)
	case words[0] == "seal" && len(words) == 5:
		aead, err := chacha20poly1305.New(unhex(words[1]))
		if err != nil {
			return "bad"
		}
		return ok(aead.Seal(nil, unhex(words[2]), unhex(words[4]), unhex(words[3])))
	case words[0] == "open" && len(words) == 5:
		aead, err := chacha20poly1305.New(unhex(words[1]))
		if err != nil {
			return "bad"
		}
		plaintext, err := aead.Open(nil, unhex(words[2]), unhex(words[4]), unhex(words[3]))
		if err != nil {
			return "err"
		}
		return ok(plaintext)
	case words[0] == "x25519" && len(words) == 3:
		out, err := curve25519.X25519(unhex(words[1]), unhex(words[2]))
		if err != nil {
			return "err"
		}
		return ok(out)
	case words[0] == "scrypt" && len(words) == 7:
		logN := number(words[1])
		if logN < 0 || logN > 62 {
			return "err"
		}
		key, err := scrypt.Key(unhex(words[5]), unhex(words[6]), 1<<logN, number(words[2]),
			number(words[3]), number(words[4]))
		if err != nil {
			return "err"
		}
		return ok(key)
	case words[0] == "sshkey" && len(words) == 3:
		return sshkey(unhex(words[1]), words[2])
	case words[0] == "encrypt" && len(words) == 4:
		return encrypt(words[1], words[2] == "1", unhex(words[3]))
	case words[0] == "encryptwith" && len(words) == 5:
		return encryptWith(unhex(words[1]), words[2], words[3] == "1", unhex(words[4]))
	case words[0] == "keygen" && len(words) == 2:
		saved := rand.Reader
		rand.Reader = &countingReader{bytes: unhex(words[1])}
		defer func() { rand.Reader = saved }()
		i, err := age.GenerateX25519Identity()
		if err != nil {
			return "bad"
		}
		return ok([]byte(i.String())) + " " + hex.EncodeToString([]byte(i.Recipient().String()))
	case words[0] == "keygenpq" && len(words) == 2:
		saved := rand.Reader
		rand.Reader = &countingReader{bytes: unhex(words[1])}
		defer func() { rand.Reader = saved }()
		i, err := age.GenerateHybridIdentity()
		if err != nil {
			return "bad"
		}
		return ok([]byte(i.String())) + " " + hex.EncodeToString([]byte(i.Recipient().String()))
	case words[0] == "recipientpq" && len(words) == 2:
		r, err := age.ParseHybridRecipient(string(unhex(words[1])))
		if err != nil {
			return "err"
		}
		return ok([]byte(r.String()))
	case words[0] == "recipient" && len(words) == 2:
		r, err := age.ParseX25519Recipient(string(unhex(words[1])))
		if err != nil {
			return "err"
		}
		return ok([]byte(r.String()))
	case words[0] == "decrypt" && len(words) == 3:
		return decrypt(words[1], unhex(words[2]))
	}
	return "bad"
}

func encrypt(spec string, armored bool, plaintext []byte) string {
	file, err := encryptFile(spec, armored, plaintext)
	if err != nil {
		return "bad"
	}
	return ok(file)
}

// countingReader gives its bytes, as crypto/rand's Reader.
type countingReader struct {
	bytes []byte
	read  int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n := copy(p, r.bytes[r.read:])
	r.read += n
	if n == 0 && len(p) > 0 {
		return 0, io.EOF
	}
	return n, nil
}

func encryptWith(random []byte, spec string, armored bool, plaintext []byte) string {
	source := &countingReader{bytes: random}
	saved := rand.Reader
	rand.Reader = source
	defer func() { rand.Reader = saved }()
	file, err := encryptFile(spec, armored, plaintext)
	if err != nil {
		return "err"
	}
	return fmt.Sprintf("%s %d", ok(file), source.read)
}

func encryptFile(spec string, armored bool, plaintext []byte) ([]byte, error) {
	var recipients []age.Recipient
	for _, s := range strings.Split(spec, ",") {
		if f, ok := strings.CutPrefix(s, "R:"); ok {
			r, err := parseRecipientsFile(unhex(f))
			if err != nil {
				return nil, err
			}
			recipients = append(recipients, r...)
			continue
		}
		if f, ok := strings.CutPrefix(s, "i:"); ok {
			contents, pass, _ := strings.Cut(f, ":")
			ids, err := parseIdentitiesFile(unhex(contents), pass)
			if err != nil {
				return nil, err
			}
			r, err := identitiesToRecipients(ids)
			if err != nil {
				return nil, err
			}
			recipients = append(recipients, r...)
			continue
		}
		if p, ok := strings.CutPrefix(s, "p:"); ok {
			pass, logN, _ := strings.Cut(p, ":")
			r, err := age.NewScryptRecipient(string(unhex(pass)))
			if err != nil {
				return nil, err
			}
			r.SetWorkFactor(number(logN))
			recipients = append(recipients, r)
			continue
		}
		if line, ok := strings.CutPrefix(s, "s:"); ok {
			r, err := agessh.ParseRecipient(string(unhex(line)))
			if err != nil {
				return nil, err
			}
			recipients = append(recipients, r)
			continue
		}
		if strings.HasPrefix(s, "age1pq1") {
			r, err := age.ParseHybridRecipient(s)
			if err != nil {
				return nil, err
			}
			recipients = append(recipients, r)
			continue
		}
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, r)
	}
	out := &bytes.Buffer{}
	var dst io.Writer = out
	var a io.WriteCloser
	if armored {
		a = armor.NewWriter(out)
		dst = a
	}
	w, err := age.Encrypt(dst, recipients...)
	if err != nil {
		return nil, err
	}
	w.Write(plaintext)
	if err := w.Close(); err != nil {
		return nil, err
	}
	if a != nil {
		if err := a.Close(); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

// What cmd/age's decrypt checks first.
const crlfMangledIntro = "age-encryption.org/v1" + "\r"
const utf16MangledIntro = "\xff\xfe" + "a\x00g\x00e\x00-\x00e\x00n\x00c\x00r\x00y\x00p\x00"

func sshkey(seed []byte, passphrase string) string {
	key := ed25519.NewKeyFromSeed(seed)
	var block *pem.Block
	var err error
	if passphrase == "-" {
		block, err = ssh.MarshalPrivateKey(key, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "", unhex(passphrase))
	}
	if err != nil {
		return "bad"
	}
	pub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		return "bad"
	}
	line := bytes.TrimSuffix(ssh.MarshalAuthorizedKey(pub), []byte("\n"))
	return ok(pem.EncodeToMemory(block)) + " " + hex.EncodeToString(line)
}

func decrypt(spec string, file []byte) string {
	var identities []age.Identity
	prompts = 0
	for _, s := range strings.Split(spec, ",") {
		if f, ok := strings.CutPrefix(s, "f:"); ok {
			contents, pass, _ := strings.Cut(f, ":")
			ids, err := parseIdentitiesFile(unhex(contents), pass)
			if err != nil {
				return outcome("identity", nil)
			}
			identities = append(identities, ids...)
			continue
		}
		if p, ok := strings.CutPrefix(s, "p:"); ok {
			pass, logN, _ := strings.Cut(p, ":")
			i, err := age.NewScryptIdentity(string(unhex(pass)))
			if err != nil {
				return "bad"
			}
			i.SetMaxWorkFactor(number(logN))
			identities = append(identities, i)
			continue
		}
		if strings.HasPrefix(s, "AGE-SECRET-KEY-PQ-1") {
			i, err := age.ParseHybridIdentity(s)
			if err != nil {
				return "bad"
			}
			identities = append(identities, i)
			continue
		}
		i, err := age.ParseX25519Identity(s)
		if err != nil {
			return "bad"
		}
		identities = append(identities, i)
	}

	// cmd/age's decrypt, its errors returned rather than printed.
	rr := bufio.NewReader(bytes.NewReader(file))
	var in io.Reader = rr
	if intro, _ := rr.Peek(len(crlfMangledIntro)); string(intro) == crlfMangledIntro ||
		string(intro) == utf16MangledIntro {
		return outcome("header", nil)
	}
	const maxWhitespace = 1024
	start, _ := rr.Peek(maxWhitespace + len(armor.Header))
	if strings.HasPrefix(string(bytes.TrimSpace(start)), armor.Header) {
		in = armor.NewReader(rr)
	}

	// As testkit_test.go tells the outcomes apart.
	r, err := age.Decrypt(in, identities...)
	if err != nil && strings.HasSuffix(err.Error(), "bad header MAC") {
		return outcome("hmac", nil)
	} else if e := new(armor.Error); errors.As(err, &e) {
		return outcome("armor", nil)
	} else if _, ok := err.(*age.NoIdentityMatchError); ok {
		return outcome("no-match", nil)
	} else if err != nil {
		return outcome("header", nil)
	}
	out, err := io.ReadAll(r)
	if err == nil {
		return outcome("success", out)
	}
	if e := new(armor.Error); errors.As(err, &e) {
		return outcome("armor", out)
	}
	return outcome("payload", out)
}

func outcome(what string, out []byte) string {
	sum := sha256.Sum256(out)
	return fmt.Sprintf("%s %d %s %d", what, len(out), hex.EncodeToString(sum[:]), prompts)
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	for {
		line, err := in.ReadString('\n')
		line = strings.TrimRight(line, "\n")
		if line != "" {
			fmt.Fprintln(out, answer(strings.Split(line, " ")))
			out.Flush()
		}
		if err != nil {
			return
		}
	}
}
