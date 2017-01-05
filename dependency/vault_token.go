package dependency

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	vaultapi "github.com/hashicorp/vault/api"
)

var (
	// Ensure implements
	_ Dependency = (*VaultTokenQuery)(nil)
)

// VaultTokenQuery is the dependency to Vault for a secret
type VaultTokenQuery struct {
	stopCh chan struct{}

	leaseID       string
	leaseDuration int

	// Since different tokens may use the same mount and action we need some
	// unique property for the HashCode function
	ID            string
	Action        string
	Mount         string
	data          map[string]interface{}
	token         *Secret
}

// NewVaultTokenQuery creates a new dependency.
func NewVaultTokenQuery(s ...string) (*VaultTokenQuery, error) {
	id := ""
	action := "renew-self"
	mount := "token"
	var rest []string
	// To maintain maximum compatibility with the previous implementation,
	// we assume that, if no argument is given, a token renewal is requested
	switch len(s) {
		case 0:
			// To allow backward’s compatibility
			log.Printf("[TRACE] (vault.token) No parameters passed, using consul-template's token")
		default:
			rest = s[3:len(s)]
			fallthrough
		case 3:
			mount = strings.Trim(s[2], "/")
			fallthrough
		case 2:
			action = strings.Trim(s[1], "/")
			id = s[0]
		case 1:
			fmt.Errorf("[ERROR] (vault_token) Expected 2 or more arguments, got %d", len(s))
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

	return &VaultTokenQuery{
		stopCh: make(chan struct{}, 1),
		ID:      id,
		Action:  action,
		Mount:   mount,
		data:    data,
	}, nil
}



// Fetch queries the Vault API
func (d *VaultTokenQuery) Fetch(clients *ClientSet, opts *QueryOptions) (interface{}, *ResponseMetadata, error) {
	select {
	case <-d.stopCh:
		return nil, nil, ErrStopped
	default:
	}

	opts = opts.Merge(&QueryOptions{})

	// If this is not the first query and we have a lease duration, sleep until we
	// try to renew.
	if opts.WaitIndex != 0 && d.token != nil && d.token.Auth.LeaseDuration != 0 {
		dur := time.Duration(d.token.Auth.LeaseDuration/2.0) * time.Second
		if dur == 0 {
			dur = time.Duration(VaultDefaultLeaseDuration)
		}

		log.Printf("[TRACE] %s: long polling for %s", d, dur)

		select {
		case <-d.stopCh:
			return nil, nil, ErrStopped
		case <-time.After(dur):
		}
	}

	// Attempt to renew the secret. If we do not have a secret or if that secret
	// is not renewable, we will attempt a (re-)read later.
	if d.token != nil && d.token.Auth.ClientToken != "" &&
		d.token.Auth.Renewable {

		// Attach the token to renew as BODY
		renew_data := make(map[string]interface{})
		renew_data["token"] = d.token.Auth.ClientToken

		log.Printf("[TRACE] %s: GET %s", d, &url.URL{
			Path:     "/v1/auth/" + d.Mount + "/renew",
			RawQuery: opts.String(),
		})

		renewal, err := clients.Vault().Logical().Write("auth/" + d.Mount + "/renew", renew_data)
		if err != nil {
			return nil, nil, errors.Wrap(err, d.String())
		}
		log.Printf("[TRACE] (%s) successfully renewed", d)

		leaseDuration := renewal.Auth.LeaseDuration
		if leaseDuration == 0 {
			log.Printf("[WARN] (%s) lease duration is 0, setting to 5s", d)
			leaseDuration = 5
		}

		d.token.Auth.LeaseDuration = leaseDuration

		// Create our cloned secret
		secretauth := &vaultapi.SecretAuth{
			ClientToken:   d.token.Auth.ClientToken,
			Accessor:      d.token.Auth.Accessor,
			Policies:      d.token.Auth.Policies,
			Metadata:      d.token.Auth.Metadata,
			LeaseDuration: leaseDuration,
			Renewable:     renewal.Auth.Renewable,
		}

		token := &Secret{
			LeaseID:       renewal.LeaseID,
			LeaseDuration: secretauth.LeaseDuration,
			Renewable:     secretauth.Renewable,
			Data:          renewal.Data,
			Auth:          secretauth,
		}

		return respWithMetadata(token)

		// The renewal failed for some reason.
		log.Printf("[WARN] (%s) failed to renew, re-obtaining: %s", d, err)
	}

	// If we got this far, we either didn't have a token to renew, the token was
	// not renewable, or the renewal failed, so attempt a fresh read.
	var vaultSecret *vaultapi.Secret
	log.Printf("[TRACE] %s: GET %s", d, &url.URL{
		Path:     "/v1/auth/" + d.Mount + "/" + d.Action,
		RawQuery: opts.String(),
	})
	vaultSecret, err := clients.Vault().Logical().Write(("auth/" + d.Mount + "/" + d.Action), d.data)

	if err != nil {
		return nil, nil, ErrWithExitf("error obtaining from vault: %s", err)
	}

	leaseDuration := leaseDurationOrDefault(vaultSecret.Auth.LeaseDuration)
	if leaseDuration == 0 {
		log.Printf("[WARN] (%s) lease duration is 0, setting to 5s", d)
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
		LeaseID:       vaultSecret.LeaseID,
		LeaseDuration: secretauth.LeaseDuration,
		Renewable:     secretauth.Renewable,
		Data:          vaultSecret.Data,
		Auth:          secretauth,
	}

	d.token = token
	// To stay compatible with the original implementation
	d.leaseDuration = token.Auth.LeaseDuration

	log.Printf("[TRACE] (%s) successfully retrieved token", d)

	return respWithMetadata(token)
}

// CanShare returns if this dependency is shareable.
func (d *VaultTokenQuery) CanShare() bool {
	return false
}

// Stop halts the dependency's fetch function.
func (d *VaultTokenQuery) Stop() {
	close(d.stopCh)
}

// String returns the human-friendly version of this dependency.
func (d *VaultTokenQuery) String() string {
	// To enable the use of defaults we have to cover the case when these
	// fields are not set
	if len(d.ID) == 0 {
		log.Printf("[DEBUG] (%s) VaultToken without ID - assuming defaults", d)

		return "vault.token"
	} else if len(d.Action) == 0 {
		// If this function is called with an empty token the defaults are assumed
		// but any Token with a custom ID also needs to have an action specified
		log.Printf("[ERROR] (%s) Invalid VaultToken - ID set but Action missing", d)
		return ""
	} else if len(d.Mount) == 0 {
		log.Printf("[DEBUG] (%s) VaultToken without Mount - assuming token", d)
		return fmt.Sprintf("vault.token|%s:token/%s", d.ID, d.Action)
	}
	return fmt.Sprintf("vault.token|%s:%s/%s", d.ID, d.Mount, d.Action)
}
