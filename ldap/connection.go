package ldap

import (
	"crypto/tls"

	"github.com/go-ldap/ldap"
)

// Connection is interface for ldap encrypted connection types.
type Connection interface {
	getConnection(address string, tlsConfig *tls.Config) (*ldap.Conn, error)
}

// TLSConnection is for using a secure tls connection over tcp to ldap.
type TLSConnection struct{}

func (t TLSConnection) getConnection(address string, tlsConfig *tls.Config) (*ldap.Conn, error) {
	return ldap.DialTLS("tcp", address, tlsConfig)
}

// STARTTLSConnection is to be used for an insecure connection converted to a tls connection over tcp to ldap.
type STARTTLSConnection struct{}

func (t STARTTLSConnection) getConnection(address string, tlsConfig *tls.Config) (*ldap.Conn, error) {
	conn, err := ldap.Dial("tcp", address)
	if err == nil {
		err = conn.StartTLS(tlsConfig)
	}
	return conn, err
}

// InsecureConnection is for using a insecure connection over tcp to ldap.
type InsecureConnection struct{}

func (t InsecureConnection) getConnection(address string, tlsConfig *tls.Config) (*ldap.Conn, error) {
	return ldap.Dial("tcp", address)
}
