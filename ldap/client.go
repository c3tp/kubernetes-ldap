package ldap

import (
	"crypto/tls"
	"fmt"

	"github.com/go-ldap/ldap"
)

// Authenticator authenticates a user against an LDAP directory
type Authenticator interface {
	Authenticate(username, password string) (*ldap.Entry, error)
	GetUserInfo(username string) (*ldap.Entry, error)
}

// Client represents a connection, and associated lookup strategy,
// for authentication via an LDAP server.
type Client struct {
	BaseDN             string
	LdapServer         string
	LdapPort           uint
	UserLoginAttribute string
	Connection         *Connection
	SearchUserDN       string
	SearchUserPassword string
	TLSConfig          *tls.Config
}

// Authenticate a user against the LDAP directory. Returns an LDAP entry if password
// is valid, otherwise returns an error.
func (c *Client) Authenticate(username, password string) (*ldap.Entry, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, fmt.Errorf("Authentication: Error opening LDAP connection: %v", err)
	}
	defer conn.Close()

	// Bind user to perform the search
	if c.SearchUserDN != "" && c.SearchUserPassword != "" {
		err = conn.Bind(c.SearchUserDN, c.SearchUserPassword)
	} else {
		err = conn.Bind(username, password)
	}
	if err != nil {
		return nil, fmt.Errorf("Error binding user to LDAP server: %v", err)
	}

	entry, err := c.getEntry(conn, username)
	if err != nil {
		return nil, err
	}

	// Now that we know the user exists within the BaseDN scope
	// let's do user bind to check credentials using the full DN instead of
	// the attribute used for search
	if c.SearchUserDN != "" && c.SearchUserPassword != "" {
		err = conn.Bind(entry.DN, password)
		if err != nil {
			return nil, fmt.Errorf("Error binding user %s, invalid credentials: %v", username, err)
		}
	}

	return entry, nil
}

// GetUserInfo queries the ldap server and tries to find a user with userinfo.
func (c *Client) GetUserInfo(username string) (*ldap.Entry, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, fmt.Errorf("Authentication: Error opening LDAP connection: %v", err)
	}
	defer conn.Close()

	return c.getEntry(conn, username)
}

func (c *Client) getEntry(conn *ldap.Conn, username string) (*ldap.Entry, error) {
	req := c.newUserSearchRequest(username)

	// Do a search to ensure the user exists within the BaseDN scope
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("Error searching for user %s: %v", username, err)
	}

	switch {
	case len(res.Entries) == 0:
		return nil, fmt.Errorf("No result for the search filter '%s'", req.Filter)
	case len(res.Entries) > 1:
		return nil, fmt.Errorf("Multiple entries found for the search filter '%s': %+v", req.Filter, res.Entries)
	}

	return res.Entries[0], nil
}

func (c *Client) getAddress() string {
	return fmt.Sprintf("%s:%d", c.LdapServer, c.LdapPort)
}

// Create a new TCP connection to the LDAP server
func (c *Client) dial() (*ldap.Conn, error) {
	connection := c.Connection
	return (*connection).getConnection(c.getAddress(), c.TLSConfig)
}

func (c *Client) newUserSearchRequest(username string) *ldap.SearchRequest {
	// TODO(abrand): sanitize
	userFilter := fmt.Sprintf("(%s=%s)", c.UserLoginAttribute, username)
	return &ldap.SearchRequest{
		BaseDN:       c.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases, // ????
		SizeLimit:    2,
		TimeLimit:    10, // make configurable?
		TypesOnly:    false,
		Filter:       userFilter,
	}
}
