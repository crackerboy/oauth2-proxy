package providers

import (
	"errors"
	"io/ioutil"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
)

// ProviderData contains information required to configure all implementations
// of OAuth2 providers
type ProviderData struct {
	ProviderName      string
	LoginURL          *url.URL
	RedeemURL         *url.URL
	ProfileURL        *url.URL
	ProtectedResource *url.URL
	ValidateURL       *url.URL
	// Auth request params & related, see
	//https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.1.1.1
	AcrValues        string
	ApprovalPrompt   string // NOTE: Renamed to "prompt" in OAuth2
	ClientID         string
	ClientSecret     string
	ClientSecretFile string
	Scope            string
	Prompt           string
}

// Data returns the ProviderData
func (p *ProviderData) Data() *ProviderData { return p }

func (p *ProviderData) GetClientSecret() (clientSecret string, err error) {
	if p.ClientSecret != "" || p.ClientSecretFile == "" {
		return p.ClientSecret, nil
	}

	// Getting ClientSecret can fail in runtime so we need to report it without returning the file name to the user
	fileClientSecret, err := ioutil.ReadFile(p.ClientSecretFile)
	if err != nil {
		logger.Printf("error reading client secret file %s: %s", p.ClientSecretFile, err)
		return "", errors.New("could not read client secret file")
	}
	return string(fileClientSecret), nil
}

func (p *ProviderData) setProviderDefaults(name string, defaultLoginURL, defaultRedeemURL, defaultProfileURL, defaultValidateURL *url.URL, defaultScope string) {
	p.ProviderName = name
	setURLDefault(&p.LoginURL, defaultLoginURL)
	setURLDefault(&p.RedeemURL, defaultRedeemURL)
	setURLDefault(&p.ProfileURL, defaultProfileURL)
	setURLDefault(&p.ValidateURL, defaultValidateURL)

	if p.Scope == "" {
		p.Scope = defaultScope
	}
}

// setURLDefault will set the url to the default given if it is empty or nil.
// If the provided default is nil, it will populate it with an empty URL to make sure it is not nil.
func setURLDefault(u **url.URL, d *url.URL) {
	if *u == nil || (*u).String() == "" {
		if d != nil {
			*u = d
		} else {
			*u = &url.URL{}
		}
	}
}
