package authz

import (
	"strings"

	"github.com/apprenda-kismatic/kubernetes-ldap/ldap"
	goldap "github.com/go-ldap/ldap"
)

// Authorizer with authorization endpoint for ldap requests.
type Authorizer struct {
	LDAPAuthenticator ldap.Authenticator
}

func (auth *Authorizer) isAuthorized(request *ReviewRequest) bool {
	return auth.partialFakeAuthz(request)
}

func (auth *Authorizer) fakeAuthz(request *ReviewRequest) bool {
	return true
}

func (auth *Authorizer) partialFakeAuthz(request *ReviewRequest) bool {
	if validQueryForFedEngine(request) || validQueryForSystem(request) {
		return true
	}

	entry, err := auth.LDAPAuthenticator.GetUserInfo(request.Status.User)
	if err != nil {
		return false
	}

	return validQuery(entry, request)
}

func validQuery(entry *goldap.Entry, request *ReviewRequest) bool {
	return validQueryForCANFARStaff(entry, request) ||
		validQueryForCCStaff(entry, request)
}

func validQueryForSystem(request *ReviewRequest) bool {
	for _, val := range request.Status.Group {
		if strings.HasPrefix(val, "system:") {
			return true
		}
	}

	return false
}

func validQueryForFedEngine(request *ReviewRequest) bool {
	return request.Status.User == "federation-controller-manager" ||
		request.Status.User == "admin"
}

func validQueryForCANFARStaff(entry *goldap.Entry, request *ReviewRequest) bool {
	if request.Status.ResourceAttributes.Namespace != "canfar" {
		return false
	}
	for _, val := range request.Status.Group {
		if val == "NRC Herzberg Institute of Astrophysics" {
			return true
		}
	}
	return false
}

func validQueryForCCStaff(entry *goldap.Entry, request *ReviewRequest) bool {
	for _, val := range request.Status.Group {
		if val == "CC: Compute Canada" {
			return true
		}
	}
	return false
}
