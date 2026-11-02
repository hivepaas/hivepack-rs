// Identity files as age -i reads them: parseIdentitiesFile, parseIdentities
// and parseSSHIdentity of cmd/age/parse.go, and LazyScryptIdentity and
// EncryptedIdentity of cmd/age/encrypted_keys.go, from age v1.3.2, which
// are in package main there. Their passphrase prompts answer the request's
// passphrase and are counted; plugins and .pub files are left out, as the
// requests have neither.
//
// Recipients as age -r and -R read them: parseRecipient, parseRecipientsFile
// and unsupportedSSHKey of cmd/age/parse.go, and identitiesToRecipients of
// cmd/age/age.go. Plugins and tagged recipients are refused, as the port does;
// its tests do not compare ssh-rsa keys age takes.
//
// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in age's LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"
)

func parseRecipient(arg string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(arg, "age1pq1"):
		return age.ParseHybridRecipient(arg)
	case strings.HasPrefix(arg, "age1") && strings.Count(arg, "1") > 1:
		return nil, errors.New("plugins and tagged recipients are refused")
	case strings.HasPrefix(arg, "age1"):
		return age.ParseX25519Recipient(arg)
	case strings.HasPrefix(arg, "ssh-"):
		return agessh.ParseRecipient(arg)
	}
	return nil, fmt.Errorf("unknown recipient type: %q", arg)
}

func parseRecipientsFile(file []byte) ([]age.Recipient, error) {
	const recipientFileSizeLimit = 16 << 20 // 16 MiB
	const lineLengthLimit = 8 << 10         // 8 KiB, same as sshd(8)
	var recs []age.Recipient
	lr := &io.LimitedReader{R: bytes.NewReader(file), N: recipientFileSizeLimit + 1}
	scanner := bufio.NewScanner(lr)
	var n int
	for scanner.Scan() {
		n++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if !utf8.ValidString(line) {
			return nil, fmt.Errorf("recipients file is not valid UTF-8")
		}
		if len(line) > lineLengthLimit {
			return nil, fmt.Errorf("line %d is too long", n)
		}
		r, err := parseRecipient(line)
		if err != nil {
			if _, unsupported := unsupportedSSHKey(line); unsupported {
				continue
			}
			if strings.HasPrefix(line, "AGE-") {
				return nil, fmt.Errorf("error at line %d: apparent identity found in recipients file", n)
			}
			return nil, fmt.Errorf("malformed recipient at line %d", n)
		}
		recs = append(recs, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read recipients file: %v", err)
	}
	if lr.N == 0 {
		return nil, fmt.Errorf("recipients file is too long")
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("no recipients found")
	}
	return recs, nil
}

func unsupportedSSHKey(s string) (string, bool) {
	fields := strings.Split(s, " ")
	if len(fields) < 2 {
		return "", false
	}
	key, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", false
	}
	k := cryptobyte.String(key)
	var typeLen uint32
	var typeBytes []byte
	if !k.ReadUint32(&typeLen) || !k.ReadBytes(&typeBytes, int(typeLen)) {
		return "", false
	}
	if t := fields[0]; t == string(typeBytes) {
		switch t {
		case "ssh-ed25519":
			return "", false
		case "ssh-rsa":
			out, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
			if err != nil {
				return "", false
			}
			cryptoKey, ok := out.(ssh.CryptoPublicKey)
			if !ok {
				return "", false
			}
			rsaKey, ok := cryptoKey.CryptoPublicKey().(*rsa.PublicKey)
			if !ok {
				return "", false
			}
			return t, rsaKey.N.BitLen() < 2048
		default:
			return t, true
		}
	}
	return "", false
}

func identitiesToRecipients(ids []age.Identity) ([]age.Recipient, error) {
	var recipients []age.Recipient
	for _, id := range ids {
		switch id := id.(type) {
		case *age.X25519Identity:
			recipients = append(recipients, id.Recipient())
		case *age.HybridIdentity:
			recipients = append(recipients, id.Recipient())
		case *agessh.Ed25519Identity:
			recipients = append(recipients, id.Recipient())
		case *agessh.EncryptedSSHIdentity:
			recipients = append(recipients, id.Recipient())
		case *EncryptedIdentity:
			r, err := id.Recipients()
			if err != nil {
				return nil, err
			}
			recipients = append(recipients, r...)
		default:
			return nil, fmt.Errorf("unexpected identity type: %T", id)
		}
	}
	return recipients, nil
}

func (i *EncryptedIdentity) Recipients() ([]age.Recipient, error) {
	if i.identities == nil {
		if err := i.decrypt(); err != nil {
			return nil, err
		}
	}
	return identitiesToRecipients(i.identities)
}

// prompts counts the passphrases asked for during a request.
var prompts int

func prompt(pass string) ([]byte, error) {
	prompts++
	if pass == "-" {
		return nil, errors.New("no passphrase")
	}
	return unhex(pass), nil
}

func parseIdentitiesFile(file []byte, pass string) ([]age.Identity, error) {
	b := bufio.NewReader(bytes.NewReader(file))
	const maxWhitespace = 1024
	p, _ := b.Peek(maxWhitespace + len(armor.Header))
	trimmed := bytes.TrimSpace(p)
	switch {
	case bytes.HasPrefix(p, []byte("age-encryption")) ||
		bytes.HasPrefix(trimmed, []byte(armor.Header)):
		var r io.Reader = b
		if bytes.HasPrefix(trimmed, []byte(armor.Header)) {
			r = armor.NewReader(r)
		}
		const privateKeySizeLimit = 1 << 24 // 16 MiB
		contents, err := io.ReadAll(io.LimitReader(r, privateKeySizeLimit))
		if err != nil {
			return nil, err
		}
		if len(contents) == privateKeySizeLimit {
			return nil, errors.New("file too long")
		}
		return []age.Identity{&EncryptedIdentity{
			Contents: contents,
			Passphrase: func() (string, error) {
				p, err := prompt(pass)
				return string(p), err
			},
		}}, nil
	case bytes.HasPrefix(trimmed, []byte("-----BEGIN")):
		const privateKeySizeLimit = 1 << 14 // 16 KiB
		contents, err := io.ReadAll(io.LimitReader(b, privateKeySizeLimit))
		if err != nil {
			return nil, err
		}
		if len(contents) == privateKeySizeLimit {
			return nil, errors.New("file too long")
		}
		return parseSSHIdentity(contents, pass)
	default:
		return parseIdentities(b)
	}
}

func parseIdentities(f io.Reader) ([]age.Identity, error) {
	const privateKeySizeLimit = 1 << 24 // 16 MiB
	var ids []age.Identity
	lr := &io.LimitedReader{R: f, N: privateKeySizeLimit + 1}
	scanner := bufio.NewScanner(lr)
	var n int
	for scanner.Scan() {
		n++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if !utf8.ValidString(line) {
			return nil, fmt.Errorf("identities file is not valid UTF-8")
		}
		var i age.Identity
		var err error
		switch {
		case strings.HasPrefix(line, "AGE-SECRET-KEY-1"):
			i, err = age.ParseX25519Identity(line)
		case strings.HasPrefix(line, "AGE-SECRET-KEY-PQ-1"):
			i, err = age.ParseHybridIdentity(line)
		default:
			err = fmt.Errorf("unknown identity type")
		}
		if err != nil {
			return nil, fmt.Errorf("error at line %d: %v", n, err)
		}
		ids = append(ids, i)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read identities file: %v", err)
	}
	if lr.N == 0 {
		return nil, fmt.Errorf("identities file is too long")
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no identities found")
	}
	return ids, nil
}

func parseSSHIdentity(pemBytes []byte, pass string) ([]age.Identity, error) {
	id, err := agessh.ParseIdentity(pemBytes)
	if sshErr, ok := err.(*ssh.PassphraseMissingError); ok {
		pubKey := sshErr.PublicKey
		if pubKey == nil {
			return nil, errors.New("no public key")
		}
		i, err := agessh.NewEncryptedSSHIdentity(pubKey, pemBytes, func() ([]byte, error) {
			return prompt(pass)
		})
		if err != nil {
			return nil, err
		}
		return []age.Identity{i}, nil
	}
	if err != nil {
		return nil, err
	}
	return []age.Identity{id}, nil
}

type LazyScryptIdentity struct {
	Passphrase func() (string, error)
}

func (i *LazyScryptIdentity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	for _, s := range stanzas {
		if s.Type == "scrypt" && len(stanzas) != 1 {
			return nil, errors.New("an scrypt recipient must be the only one")
		}
	}
	if len(stanzas) != 1 || stanzas[0].Type != "scrypt" {
		return nil, age.ErrIncorrectIdentity
	}
	pass, err := i.Passphrase()
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase: %v", err)
	}
	ii, err := age.NewScryptIdentity(pass)
	if err != nil {
		return nil, err
	}
	fileKey, err = ii.Unwrap(stanzas)
	if errors.Is(err, age.ErrIncorrectIdentity) {
		return nil, fmt.Errorf("incorrect passphrase")
	}
	return fileKey, err
}

type EncryptedIdentity struct {
	Contents   []byte
	Passphrase func() (string, error)

	identities []age.Identity
}

func (i *EncryptedIdentity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	if i.identities == nil {
		if err := i.decrypt(); err != nil {
			return nil, err
		}
	}

	for _, id := range i.identities {
		fileKey, err = id.Unwrap(stanzas)
		if errors.Is(err, age.ErrIncorrectIdentity) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return fileKey, nil
	}
	return nil, age.ErrIncorrectIdentity
}

func (i *EncryptedIdentity) decrypt() error {
	d, err := age.Decrypt(bytes.NewReader(i.Contents), &LazyScryptIdentity{i.Passphrase})
	if e := new(age.NoIdentityMatchError); errors.As(err, &e) {
		return fmt.Errorf("identity file is encrypted with age but not with a passphrase")
	}
	if err != nil {
		return fmt.Errorf("failed to decrypt identity file: %v", err)
	}
	i.identities, err = parseIdentities(d)
	return err
}
