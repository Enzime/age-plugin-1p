package main

import (
	"bufio"
	"bytes"
	"strings"

	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"

	page "filippo.io/age/plugin"
	pw "github.com/Enzyme/age-plugin-pwmanager/internal/pwmanager"

	"golang.org/x/crypto/ssh"
)

func (opw OnePassword) FullPluginName() string {
	return "age-plugin-1p"
}

func (opw OnePassword) PluginName() string {
	return "1p"
}

type OnePassword struct{}

func (opw OnePassword) CreateIdentityFromPath(privateKeyPath string) (*pw.Identity, error) {
	privateKey, err := opw.ReadKeyFromPath(privateKeyPath)
	if err != nil {
		return nil, err
	}

	return pw.NewIdentity(privateKey)
}

func (opw OnePassword) ParseIdentity(f io.Reader) (*pw.Identity, error) {
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

		identity, err := opw.DecodeIdentity(line)
		if err != nil {
			return nil, fmt.Errorf("error at line %d: %v", n, err)
		}
		return identity, nil
	}
	return nil, fmt.Errorf("no identities found")
}

func (opw OnePassword) DecodeIdentity(pluginIdentityString string) (*pw.Identity, error) {
	var key pw.Identity

	name, b, err := page.ParseIdentity(pluginIdentityString)
	if err != nil {
		return nil, err
	}
	if name != opw.PluginName() {
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

	privateKey, err := opw.ReadKeyFromPubKey(publicKey)
	if err != nil {
		return nil, err
	}

	key.PrivKey = privateKey

	return &key, nil
}

func (opw OnePassword) NewDefaultIdentity() (*pw.DefaultIdentity, error) {
	identities, err := opw.GetAllIdentities()
	if err != nil {
		return nil, err
	}

	d := pw.NewDefaultIdentity(identities)
	return d, nil
}

func (opw OnePassword) MarshalAllRecipients() (out string, err error) {
	privateKeysForOpRef, err := opw.ReadAllKeys()
	if err != nil {
		return "", err
	}
	for opRef, privateKey := range privateKeysForOpRef {
		identity, err := pw.NewIdentity(privateKey)
		if err != nil {
			return "", err
		}

		out += fmt.Sprintf("%s: %s\n", opRef, identity.Recipient())
	}
	return
}

// ReadKeyFromPath reads a given path/reference inside the password manager and returns the key
// It is analogous to the CLI command:
// `op read op://app-prod/db/password`
func (opw OnePassword) ReadKeyFromPath(path string) (key []byte, err error) {
	cmd := exec.Command("op", "read", path)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("could not read key from 1Password at: %v: %v", path, err)
	}
	return output, nil
}

func (opw OnePassword) ListSSHFingerprints() (output []byte, err error) {
	cmd := exec.Command("op", "item", "list", "--categories", "SSH Key", "--format=json")
	output, err = cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("could not get list of SSH keys from 1Password: %v", err)
	}
	return
}

func (opw OnePassword) UnmarshalItemList(output []byte) (items []map[string]any, err error) {
	err = json.Unmarshal(output, &items)
	if err != nil {
		return nil, fmt.Errorf("could not decode list of SSH keys from 1Password: %v", err)
	}
	return
}

// ReadKeyFromPubKey retrieves the private key for a given public key from the
// password manager
func (opw OnePassword) ReadKeyFromPubKey(pubKey ssh.PublicKey) (privateKey []byte, err error) {
	fingerprint := ssh.FingerprintSHA256(pubKey)

	output, err := opw.ListSSHFingerprints()
	if err != nil {
		return nil, err
	}

	items, err := opw.UnmarshalItemList(output)
	if err != nil {
		return nil, err
	}

	var privateKeyPath string

	for _, item := range items {
		additional_information := item["additional_information"].(string)

		if additional_information == fingerprint {
			vault := item["vault"].(map[string]any)
			privateKeyPath = fmt.Sprintf("op://%s/%s/private key", vault["id"], item["id"])
			break
		}
	}

	if privateKeyPath == "" {
		return nil, fmt.Errorf("private key not found in 1Password for public key: %s", ssh.MarshalAuthorizedKey(pubKey))
	}

	return opw.ReadKeyFromPath(privateKeyPath)
}

func (opw OnePassword) ReadAllKeys() (privateKeyFromOpRef map[string][]byte, err error) {
	opItemList := exec.Command("op", "item", "list", "--categories", "SSH Key", "--format=json")
	opItemGet := exec.Command("op", "item", "get", "-", "--fields", "private_key", "--format=json")

	outPipe, err := opItemList.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to list SSH keys from 1Password: %v", err)
	}
	defer outPipe.Close()

	opItemList.Start()
	opItemGet.Stdin = outPipe
	output, err := opItemGet.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get SSH keys from 1Password: %v", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(output))
	privateKeyFromOpRef = make(map[string][]byte)

	for {
		var item map[string]any
		err := decoder.Decode(&item)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to decode SSH keys from 1Password: %v", err)
		}

		value := []byte(item["value"].(string))
		reference := item["reference"].(string)
		privateKeyFromOpRef[reference] = value
	}
	return
}

func (opw OnePassword) GetAllIdentities() (identities []pw.Identity, err error) {
	privateKeyForRef, err := opw.ReadAllKeys()
	if err != nil {
		return nil, err
	}

	for _, privateKey := range privateKeyForRef {
		i, err := pw.NewIdentity(privateKey)
		if err != nil {
			return nil, err
		}
		identities = append(identities, *i)
	}
	return
}
