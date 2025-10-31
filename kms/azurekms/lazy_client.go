//go:build !noazurekms

package azurekms

import (
	"fmt"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

type lazyClientFunc func(vaultURL string) (KeyVaultClient, error)

type lazyClient struct {
	rw        sync.RWMutex
	clients   map[string]KeyVaultClient
	new       lazyClientFunc
	dnsSuffix string
}

func newLazyClient(dnsSuffix string, fn lazyClientFunc) *lazyClient {
	return &lazyClient{
		clients:   make(map[string]KeyVaultClient),
		new:       fn,
		dnsSuffix: dnsSuffix,
	}
}

func (l *lazyClient) Get(vault string) (KeyVaultClient, error) {
	vaultURL := vaultBaseURL(vault, l.dnsSuffix)
	// Get an already initialize client
	l.rw.RLock()
	c, ok := l.clients[vaultURL]
	l.rw.RUnlock()
	if ok {
		return c, nil
	}

	// Create a new client
	c, err := l.new(vaultURL)
	if err != nil {
		return nil, fmt.Errorf("error creating client for vault %q: %w", vaultURL, err)
	}

	l.rw.Lock()
	l.clients[vaultURL] = c
	l.rw.Unlock()
	return c, nil
}

func lazyClientCreator(credential azcore.TokenCredential) lazyClientFunc {
	return func(vaultURL string) (KeyVaultClient, error) {
		return azkeys.NewClient(vaultURL, credential, &azkeys.ClientOptions{
			// See https://aka.ms/azsdk/blog/vault-uri
			DisableChallengeResourceVerification: true,
		})
	}
}

func vaultBaseURL(vault, dnsSuffix string) string {
	return "https://" + vault + "." + dnsSuffix + "/"
}
