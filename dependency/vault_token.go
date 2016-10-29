package dependency

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// VaultToken is the dependency to Vault for a secret
type VaultToken struct {
	sync.Mutex

	leaseID       string
	leaseDuration int

	// Since different tokens may use the same mount and action we need some
	// unique property for the HashCode function
	ID            string
	Action        string
	Mount         string
	data          map[string]interface{}
	token         *Secret

	stopped bool
	stopCh  chan struct{}
}

// Fetch queries the Vault API
func (d *VaultToken) Fetch(clients *ClientSet, opts *QueryOptions) (interface{},
		*ResponseMetadata, error) {
	d.Lock()
	if d.stopped {
		defer d.Unlock()
		return nil, nil, ErrStopped
	}
	d.Unlock()

	if opts == nil {
		opts = &QueryOptions{}
	}

	log.Printf("[DEBUG] (%s) Retrieving vault token", d.Display())

	// If this is not the first query and we have a lease duration, sleep until we
	// try to renew.
	if opts.WaitIndex != 0 && d.token != nil && d.token.Auth.LeaseDuration != 0 {
		duration := time.Duration(d.token.Auth.LeaseDuration/2.0) * time.Second

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
		return nil, nil, ErrWithExitf("vault_token: %s", err)
	}

	// Attempt to renew the secret. If we do not have a secret or if that secret
	// is not renewable, we will attempt a (re-)read later.
	if d.token != nil && d.token.Auth.ClientToken != "" &&
		d.token.Auth.Renewable {

		// Attach the token to renew as BODY
		renew_data := make(map[string]interface{})
		renew_data["token"] = d.token.Auth.ClientToken

		renewal, err := vault.Logical().Write("auth/" + d.Mount + "/renew",
				renew_data)
		if err == nil {
			log.Printf("[DEBUG] (%s) successfully renewed", d.Display())

			leaseDuration := renewal.Auth.LeaseDuration
			if leaseDuration == 0 {
				log.Printf("[WARN] (%s) lease duration is 0, setting to 5s",
					d.Display())
				leaseDuration = 5
			}

			d.Lock()
			d.token.Auth.LeaseDuration = leaseDuration
			d.Unlock()

			// Create our cloned secret
			secretauth := &vaultapi.SecretAuth{
				ClientToken:   d.token.Auth.ClientToken,
				Accessor:      d.token.Auth.Accessor,
				Policies:      d.token.Auth.Policies,
				Metadata:      d.token.Auth.Metadata,
				LeaseDuration: d.token.Auth.LeaseDuration,
				Renewable:     d.token.Auth.Renewable,
			}

			token := &Secret{
				LeaseDuration: secretauth.LeaseDuration,
				Auth:          secretauth,
			}

			return respWithMetadata(token)
		}

		// The renewal failed for some reason.
		log.Printf("[WARN] (%s) failed to renew, re-obtaining: %s", d.Display(),
			err)
	}

	// If we got this far, we either didn't have a token to renew, the token was
	// not renewable, or the renewal failed, so attempt a fresh read.
	var vaultSecret *vaultapi.Secret
	vaultSecret, err = vault.Logical().Write(("auth/" + d.Mount + "/" + d.Action),
		d.data)

	if err != nil {
		return nil, nil, ErrWithExitf("error obtaining from vault: %s", err)
	}

	leaseDuration := leaseDurationOrDefault(vaultSecret.Auth.LeaseDuration)
	if leaseDuration == 0 {
		log.Printf("[WARN] (%s) lease duration is 0, setting to 5s", d.Display())
		leaseDuration = 5
	}

	// Create our cloned secret
	secretauth := &vaultapi.SecretAuth{
		ClientToken:   vaultSecret.Auth.ClientToken,
		Accessor:      vaultSecret.Auth.Accessor,
		Policies:      vaultSecret.Auth.Policies,
		Metadata:      vaultSecret.Auth.Metadata,
		LeaseDuration: leaseDuration,
		Renewable:     vaultSecret.Auth.Renewable,
	}

	token := &Secret{
		LeaseDuration: secretauth.LeaseDuration,
		Auth:          secretauth,
	}

	d.Lock()
	d.token = token
		// To stay compatible with the original implementation
	d.leaseDuration = token.Auth.LeaseDuration
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
	// To enable the use of defaults we have to cover the case when these
	// fields are not set
	if len(d.ID) == 0 {
		log.Printf("[DEBUG] (%s) VaultToken without ID - assuming defaults",
			d.Display())
		return "VaultToken|consul-template:token/renew-self"
	}	else if len(d.Action) == 0 {
		// If this function is called with an empty token the defaults are assumed
		// but any Token with a custom ID also needs to have an action specified
		log.Printf("[ERROR] (%s) Invalid VaultToken - ID set but Action missing",
			d.Display())
		return ""
	}	else if len(d.Mount) == 0 {
		log.Printf("[DEBUG] (%s) VaultToken without Mount - assuming token",
			d.Display())
		return fmt.Sprintf("VaultToken|%s:token/%s", d.ID, d.Action)
	}

	return fmt.Sprintf("VaultToken|%s:%s/%s", d.ID, d.Mount, d.Action)
}

// Display returns a string that should be displayed to the user in output (for
// example).
func (d *VaultToken) Display() string {
	return fmt.Sprintf(`"VaultToken(%s:%s/%s)"`, d.ID, d.Mount, d.Action)
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
func ParseVaultToken(s ...string) (*VaultToken, error) {
	id := "consul-template"
	action := "renew-self"
	mount := "token"
	var rest []string
	// To maintain maximum compatibility with the previous implementation,
	// we assume that, if no argument is given, a token renewal is requested
	switch len(s) {
	case 0:
		// To allow backward’s compatibility
		log.Printf("[DEBUG] (vault_token) No parameters passed, using " +
			"consul-template's token")
	default:
		rest = s[3:len(s)]
		fallthrough
	case 3:
		mount = s[2]
		fallthrough
	case 2:
		action = s[1]
		id = s[0]
	case 1:
		log.Printf("[ERROR] (vault_token) Expected 2 or more arguments, got %d",
			len(s))
		return nil, fmt.Errorf("expected 2 or more arguments, got %d", len(s))
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
		ID:      id,
		Action:  action,
		Mount:   mount,
		data:    data,
		stopCh:  make(chan struct{}),
	}
	return vs, nil
}
