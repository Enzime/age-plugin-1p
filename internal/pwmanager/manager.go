package pwmanager

import (
	"io"
	"log"
)

var (
	Log     *log.Logger
	Backend string
)

type PwManager interface {

	// CreateIdentityFromPath creates a new identity from a given reference.
	// The reference is a path or ID or the name inside the password manager
	// backend
	CreateIdentityFromPath(privateKeyPath string) (*Identity, error)

	ParseIdentity(f io.Reader) (*Identity, error)

	// DecodeIdentity constructs an Identity from a pluginIdentityString.
	DecodeIdentity(pluginIdentityString string) (*Identity, error)

	// NewDefaultIdentity constructs a DefaultIdentity, which is a list of all
	// SSH-Keys found in the vault
	NewDefaultIdentity() (*DefaultIdentity, error)

	// MarshalAllRecipients returns all recipients (public keys) from the vault in
	// a readable format, e.g.:
	// f441244b-cba4-403e-92dc-b00b3bd7428b (me@host1): ssh-ed25519 AAAAC3NzaCxxxx...
	// 9fa82648-e32f-4127-acb2-69b052a88485 (me@host2): ssh-ed25519 AAAAC3NzaCxxxx...
	MarshalAllRecipients() (out string, err error)

	// FullPluginName returns the name of the plugin, e.g. `age-plugin-1p`
	FullPluginName() string

	//PluginName returns the shortened name of the plugin, e.g. `1p`
	PluginName() string
}
