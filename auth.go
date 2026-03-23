package sseor

import (
	"encoding/json"
	"slices"
	"time"
)

// Claims represents OIDC token claims
type Claims struct {
	Exp            int64    `json:"exp"`
	Iat            int64    `json:"iat"`
	Jti            string   `json:"jti"`
	Iss            string   `json:"iss"`
	Aud            []string `json:"aud"`
	Id             string   `json:"sub"`
	Typ            string   `json:"typ"`
	Azp            string   `json:"azp"`
	Acr            string   `json:"acr"`
	AllowedOrigins []string `json:"allowed-origins"`

	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`

	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`

	Scope             string `json:"scope"`
	Sid               string `json:"sid,omitempty"`
	SessionState      string `json:"session_state,omitempty"`
	Country           string `json:"country,omitempty"`
	State             string `json:"state,omitempty"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	Email             string `json:"email,omitempty"`
	ClientHost        string `json:"clientHost,omitempty"`
	ClientAddress     string `json:"clientAddress,omitempty"`
	ClientID          string `json:"client_id,omitempty"`
}

// ExpiresAt returns the expiration time as time.Time
func (c *Claims) ExpiresAt() time.Time {
	return time.Unix(c.Exp, 0)
}

// IssuedAt returns the issue time as time.Time
func (c *Claims) IssuedAt() time.Time {
	return time.Unix(c.Iat, 0)
}

// IsExpired checks if the token has expired
func (c *Claims) IsExpired() bool {
	return time.Now().After(c.ExpiresAt())
}

func (c *Claims) HasRole(role string) bool {
	return slices.Contains(c.RealmAccess.Roles, role)
}

func (c *Claims) IsClientToken() bool {
	// If preferred_username starts with "service-account-" it's a client credentials token
	if len(c.PreferredUsername) >= 16 && c.PreferredUsername[:15] == "service-account" {
		return true
	}

	// If there is no email or name, and client_id is present, it's probably a client token
	if c.ClientID != "" && c.Name == "" && c.Email == "" {
		return true
	}

	return false
}

func (c *Claims) GetRole() string {
	defaultRoles := []string{
		"default-roles-shooters",
		"default-roles-gh-realm",
		"offline_access",
		"uma_authorization",
	}

	for _, role := range c.RealmAccess.Roles {
		if !slices.Contains(defaultRoles, role) {
			return role
		}
	}

	return ""
}

func (c *Claims) String() string {
	jb, _ := json.MarshalIndent(c, "", " \t")
	return string(jb)
}

// GetUserID returns the user ID from claims, preferring the sub claim
func (c *Claims) GetUserID() string {
	if c.Id != "" {
		return c.Id
	}
	if c.PreferredUsername != "" {
		return c.PreferredUsername
	}
	if c.Email != "" {
		return c.Email
	}
	return ""
}
