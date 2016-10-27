package dependency

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Token is a vault token.
type Token struct {
	ClientToken   string
	Accessor      string
	Policies      []string
	Metadata      map[string]string

	LeaseDuration int
	Renewable     bool
}

// VaultToken is the dependency to Vault for a secret
type VaultToken struct {
	sync.Mutex

	leaseDuration int
	Path          string
	data          map[string]interface{}
	token         *Token

	stopped bool
	stopCh  chan struct{}
}


// Fetch queries the Vault API
func (d *VaultToken) Fetch(clients *ClientSet, opts *QueryOptions) (interface{}, *ResponseMetadata, error) {
	d.Lock()
	if d.stopped {
		defer d.Unlock()
		return nil, nil, ErrStopped
	}
	d.Unlock()

	if opts == nil {
		opts = &QueryOptions{}
	}

	log.Printf("[DEBUG] (%s) querying vault for token with %+v", d.Display(), opts)

	// If this is not the first query and we have a lease duration, sleep until we
	// try to renew.
	if opts.WaitIndex != 0 && d.token != nil && d.token.LeaseDuration != 0 {
		duration := time.Duration(d.token.LeaseDuration/2.0) * time.Second

		if duration < 1*time.Second {
			log.Printf("[DEBUG] (%s) increasing sleep to 1s (was %q)",
				d.Display(), duration)
			duration = 1 * time.Second
		}

		log.Printf("[DEBUG] (%s) sleeping for %q", d.Display(), duration)
		select {
		case <-d.stopCh:
			log.Printf("[DEBUG] (%s) received interrupt", d.Display())
			return nil, nil, ErrStopped
		case <-time.After(duration):
		}
	}

	// Grab the vault client
	vault, err := clients.Vault()
	if err != nil {
		return nil, nil, ErrWithExitf("vault token: %s", err)
	}

	// Attempt to renew the secret. If we do not have a secret or if that secret
	// is not renewable, we will attempt a (re-)read later.
	if d.token != nil && d.token.ClientToken != "" && d.token.Renewable {
		renewal, err := vault.Auth().Token().Renew(d.token.ClientToken, 0)
		if err == nil {
			log.Printf("[DEBUG] (%s) successfully renewed", d.Display())

			log.Printf("[DEBUG] (%s) %#v", d.Display(), renewal)

			leaseDuration := renewal.Auth.LeaseDuration
			if leaseDuration == 0 {
				log.Printf("[WARN] (%s) lease duration is 0, setting to 5s", d.Display())
				leaseDuration = 5
			}

			d.Lock()
			// To stay compatible with the original implementation
			d.leaseDuration = leaseDuration
			d.token.LeaseDuration = leaseDuration
			d.Unlock()

			// Create our cloned secret
			token := &Token{
				ClientToken:   d.token.ClientToken,
				Accessor:      d.token.Accessor,
				Policies:      d.token.Policies,
				Metadata:      d.token.Metadata,
				LeaseDuration: d.token.LeaseDuration,
				Renewable:     d.token.Renewable,
			}

			return respWithMetadata(token)
		}

		// The renewal failed for some reason.
		log.Printf("[WARN] (%s) failed to renew, re-obtaining: %s", d.Display(), err)
	}

	// If we got this far, we either didn't have a token to renew, the token was
	// not renewable, or the renewal failed, so attempt a fresh read.
	var vaultSecret *vaultapi.Secret
	vaultSecret, err = vault.Logical().Write(d.Path, d.data)

	if err != nil {
		return nil, nil, ErrWithExitf("error obtaining from vault: %s", err)
	}

	// Create our cloned secret
	token := &Token{
		ClientToken:   vaultSecret.Auth.ClientToken,
		Accessor:      vaultSecret.Auth.Accessor,
		Policies:      vaultSecret.Auth.Policies,
		Metadata:      vaultSecret.Auth.Metadata,
		LeaseDuration: leaseDurationOrDefault(vaultSecret.Auth.LeaseDuration),
		Renewable:     vaultSecret.Auth.Renewable,
	}

	d.Lock()
	d.token = token
		// To stay compatible with the original implementation
	d.leaseDuration = token.LeaseDuration
	d.Unlock()

	log.Printf("[DEBUG] (%s) successfully retrieved token", d.Display())

	return respWithMetadata(token)
}

// CanShare returns if this dependency is shareable.
func (d *VaultToken) CanShare() bool {
	return false
}

// HashCode returns the hash code for this dependency.
func (d *VaultToken) HashCode() string {
	return fmt.Sprintf("VaultToken|%s", d.Path)
}

// Display returns a string that should be displayed to the user in output (for
// example).
func (d *VaultToken) Display() string {
	return fmt.Sprintf(`"vault_token(%s)"`, d.Path)
}

// Stop halts the dependency's fetch function.
func (d *VaultToken) Stop() {
	d.Lock()
	defer d.Unlock()

	if !d.stopped {
		close(d.stopCh)
		d.stopped = true
	}
}


// ParseVaultToken creates a new VaultToken dependency.
//func ParseVaultToken() (*VaultToken, error) {
//	return &VaultToken{stopCh: make(chan struct{})}, nil
//}

// ParseVaultToken creates a new VaultToken dependency.
func ParseVaultToken(s ...string) (*VaultToken, error) {
	if len(s) == 0 {
		return nil, fmt.Errorf("expected 1 or more arguments, got %d", len(s))
	}

	path, rest := s[0], s[1:len(s)]

	if len(path) == 0 {
		return nil, fmt.Errorf("vault path must be at least one character")
	}

	data := make(map[string]interface{})
	for _, str := range rest {
		parts := strings.SplitN(str, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid value %q - must be key=value", str)
		}

		k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		data[k] = v
	}

	vs := &VaultToken{
		Path:   path,
		data:   data,
		stopCh: make(chan struct{}),
	}
	return vs, nil
}
