package pwmanager

import (
	"filippo.io/age"
	page "filippo.io/age/plugin"
)

type DefaultIdentity struct {
	identities []Identity
}

func NewDefaultIdentity(i []Identity) *DefaultIdentity {
	return &DefaultIdentity{
		identities: i,
	}
}

func (d *DefaultIdentity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	for _, identity := range d.identities {
		fileKey, err := identity.Unwrap(stanzas)
		if err == age.ErrIncorrectIdentity {
			continue
		} else if err == nil {
			return fileKey, nil
		}

		return nil, err
	}
	return nil, age.ErrIncorrectIdentity
}

func EncodeDefaultIdentity() string {
	return page.EncodeIdentity(pwManager.PluginName(), nil)
}
