package pwmanager

import (
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/agessh"
	page "filippo.io/age/plugin"
	"golang.org/x/crypto/ssh"
)

type Recipient struct {
	PubKey ssh.PublicKey
}

func (r *Recipient) String() string {
	return EncodeRecipient(r)
}

func (r *Recipient) agesshRecipient() (age.Recipient, error) {
	switch t := r.PubKey.Type(); t {
	case "ssh-ed25519":
		return agessh.NewEd25519Recipient(r.PubKey)
	case "ssh-rsa":
		return agessh.NewRSARecipient(r.PubKey)
	default:
		return nil, fmt.Errorf("unsupported SSH public key type: %s", t)
	}
}

func (r *Recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	agesshRecipient, err := r.agesshRecipient()
	if err != nil {
		return nil, err
	}
	return agesshRecipient.Wrap(fileKey)
}

func NewRecipient(publicKey ssh.PublicKey) *Recipient {
	return &Recipient{
		PubKey: publicKey,
	}
}

func EncodeRecipient(recipient *Recipient) string {
	authorizedKey := ssh.MarshalAuthorizedKey(recipient.PubKey)
	// drop the trailing newline
	return string(authorizedKey[:len(authorizedKey)-1])
}

func MarshalRecipient(pubkey *Recipient, w io.Writer) error {
	recipient := EncodeRecipient(pubkey)
	fmt.Fprintf(w, "%s\n", recipient)
	return nil
}

func (r *Recipient) MarshalWithDefaultIdentity(w io.Writer) error {
	WriteMarshalHeader(w)
	fmt.Fprintf(w, "# Recipient: %s\n", r)
	fmt.Fprintf(w, "\n%s\n", EncodeDefaultIdentity())
	return nil
}

func DecodeRecipient(s string) (*Recipient, error) {
	name, b, err := page.ParseRecipient(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode recipient: %v", err)
	}
	if name != pwManager.PluginName() {
		return nil, fmt.Errorf("invalid plugin for type %s", name)
	}

	publicKey, err := ssh.ParsePublicKey(b)
	if err != nil {
		return nil, err
	}

	return NewRecipient(publicKey), nil
}
