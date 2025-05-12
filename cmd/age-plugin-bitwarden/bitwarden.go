package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"

	page "filippo.io/age/plugin"
	pw "github.com/Enzyme/age-plugin-pwmanager/internal/pwmanager"
	"golang.org/x/crypto/ssh"
)

func (bw Bitwarden) PluginName() string {
	return "bitwarden"
}

func (bw Bitwarden) FullPluginName() string {
	return "age-plugin-bitwarden"
}

type Bitwarden struct{}

type BwSshItem struct {
	ID     string `json:"id"`
	Type   int    `json:"type"`
	Name   string `json:"name"`
	SSHKey struct {
		PrivateKey     string `json:"privateKey"`
		PublicKey      string `json:"publicKey"`
		KeyFingerprint string `json:"keyFingerprint"`
	} `json:"sshKey"`
	// PasswordHistory interface{} `json:"passwordHistory"`
	// RevisionDate    time.Time   `json:"revisionDate"`
	// CreationDate    time.Time   `json:"creationDate"`
	// DeletedDate     interface{} `json:"deletedDate"`
	// Object          string      `json:"object"`
	// OrganizationID  interface{} `json:"organizationId"`
	// FolderID        interface{} `json:"folderId"`
	// Reprompt        int         `json:"reprompt"`
	// Notes           interface{} `json:"notes"`
	// Favorite        bool        `json:"favorite"`
	// CollectionIds []interface{} `json:"collectionIds"`
}

func (bwi BwSshItem) toIdentity() (*pw.Identity, error) {
	return pw.NewIdentity([]byte(bwi.SSHKey.PrivateKey))
}

func (bw Bitwarden) BwSshItems() (items []BwSshItem, err error) {

	var allItems = []BwSshItem{}

	cmd := exec.Command("bw", "list", "items", "--nointeraction", "--raw")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	output, err := cmd.Output()

	if err != nil {
		log.Printf("Error executing bw-cli: %v\n", err)
		log.Printf("Stderr: %s\n", stderr.String())
		log.Printf("Make sure you are logged in (i.e. `BW_SESSION` environment variable is correctly set)")
		return items, err
	}

	if err := json.Unmarshal(output, &allItems); err != nil {
		log.Println("Error parsing bw output")
		log.Printf("Stderr: %s\n", stderr.String())
		return items, err
	}

	// Filter for "type = 5" (The SSH-Key type in bitwarden)
	for _, item := range allItems {
		if item.Type == 5 {
			items = append(items, item)
		}
	}

	return
}

func (bw Bitwarden) DecodeIdentity(pluginIdentityString string) (*pw.Identity, error) {
	log.Println("Trying to decode string:", pluginIdentityString)

	var key pw.Identity

	name, b, err := page.ParseIdentity(pluginIdentityString)
	if err != nil {
		return nil, err
	}
	if name != bw.PluginName() {
		return nil, fmt.Errorf("invalid hrp")
	}
	r := bytes.NewBuffer(b)
	for _, f := range key.Serialize() {
		if err := binary.Read(r, binary.BigEndian, f); err != nil {
			return nil, err
		}
	}

	publicKey, err := ssh.ParsePublicKey(r.Bytes())
	if err != nil {
		return nil, err
	}

	key.PubKey = publicKey

	keys, err := bw.BwSshItems()
	if err != nil {
		return nil, err
	}

	// Get fingerprint of public key and try to find it in the vault
	fingerprint := ssh.FingerprintSHA256(publicKey)

	for _, k := range keys {
		if fingerprint == k.SSHKey.KeyFingerprint {
			key.PrivKey = []byte(k.SSHKey.PrivateKey)
			return &key, nil
		}
	}

	return nil, errors.New("Unable to find key")
}

func (bw Bitwarden) NewDefaultIdentity() (*pw.DefaultIdentity, error) {

	identities := []pw.Identity{}

	allkeys, err := bw.BwSshItems()
	if err != nil {
		return nil, err
	}

	for _, key := range allkeys {
		i, err := pw.NewIdentity([]byte(key.SSHKey.PrivateKey))
		if err != nil {
			return nil, err
		}
		identities = append(identities, *i)
	}

	d := pw.NewDefaultIdentity(identities)
	return d, nil
}

func (bw Bitwarden) MarshalAllRecipients() (out string, err error) {

	var items []BwSshItem

	if items, err = bw.BwSshItems(); err != nil {
		return
	}

	for _, item := range items {
		if identity, err := item.toIdentity(); err != nil {
			return "", err
		} else {
			out += fmt.Sprintf("%s (%s): %s\n", item.ID, item.Name, identity.Recipient())
		}
	}

	return
}

func (bw Bitwarden) CreateIdentityFromPath(keyRef string) (*pw.Identity, error) {

	items, err := bw.BwSshItems()
	if err != nil {
		return nil, err
	}

	// Find first item who's name or ID matches
	for _, item := range items {
		if item.ID == keyRef || item.Name == strings.TrimSpace(keyRef) {
			return item.toIdentity()
		}
	}

	return nil, errors.New("No matching idententy found for: " + keyRef)
}

func (bw Bitwarden) ParseIdentity(f io.Reader) (*pw.Identity, error) {
	// Same parser as age
	const privateKeySizeLimit = 1 << 24 // 16 MiB
	scanner := bufio.NewScanner(io.LimitReader(f, privateKeySizeLimit))
	var n int
	for scanner.Scan() {
		n++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		identity, err := bw.DecodeIdentity(line)
		if err != nil {
			return nil, fmt.Errorf("error at line %d: %v", n, err)
		}
		return identity, nil
	}
	return nil, fmt.Errorf("no identities found")
}
