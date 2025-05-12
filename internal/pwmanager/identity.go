package pwmanager

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	page "filippo.io/age/plugin"
	"golang.org/x/crypto/ssh"
)

type Identity struct {
	Version uint8
	PubKey  ssh.PublicKey
	PrivKey []byte
}

func (i *Identity) Serialize() []any {
	return []any{&i.Version}
}

func (i *Identity) Recipient() *Recipient {
	return NewRecipient(i.PubKey)
}

func (i *Identity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	ageIdentity, err := agessh.ParseIdentity(i.PrivKey)
	if err != nil {
		return nil, err
	}
	switch i := ageIdentity.(type) {
	case *agessh.RSAIdentity:
		return i.Unwrap(stanzas)
	case *agessh.Ed25519Identity:
		return i.Unwrap(stanzas)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", i)
	}
}

func NewIdentity(privateKey []byte) (*Identity, error) {
	// use agessh to check the identity can be parsed
	_, err := agessh.ParseIdentity(privateKey)
	if err != nil {
		return nil, err
	}

	// TODO: use agesshIdentity.SshKey instead when it hopefully gets exposed
	sshKey, err := ssh.ParseRawPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.NewSignerFromKey(sshKey)
	if err != nil {
		return nil, err
	}

	identity := &Identity{
		Version: 1,
		PubKey:  signer.PublicKey(),
		PrivKey: privateKey,
	}

	return identity, nil
}

func EncodeIdentity(i *Identity) string {
	var b bytes.Buffer
	for _, v := range i.Serialize() {
		binary.Write(&b, binary.BigEndian, v)
	}

	binary.Write(&b, binary.BigEndian, i.PubKey.Marshal())

	return page.EncodeIdentity(pwManager.PluginName(), b.Bytes())
}

var (
	marshalTemplate = `
# Created: %s
`
)

func WriteMarshalHeader(w io.Writer) {
	s := fmt.Sprintf(marshalTemplate, time.Now())
	s = strings.TrimSpace(s)
	fmt.Fprintf(w, "%s\n", s)
}

func (i *Identity) Marshal(w io.Writer) error {
	WriteMarshalHeader(w)
	fmt.Fprintf(w, "# Recipient: %s\n", i.Recipient())
	fmt.Fprintf(w, "\n%s\n", EncodeIdentity(i))
	return nil
}
