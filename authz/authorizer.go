package authz

import (
	"encoding/json"
	"net/http"

	"github.com/apprenda-kismatic/kubernetes-ldap/ldap"
	"github.com/golang/glog"
)

// Authorizer with authorization endpoint for ldap requests.
type Authorizer struct {
	LDAPAuthenticator *ldap.Client
}

func (auth *Authorizer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		resp.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	jsonRequest, err := unmarshallJSONRequest(req)
	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		glog.Errorf("Error unmarshalling request: %v", err)
		return
	}
	defer req.Body.Close()

	if isAuthorized(jsonRequest) {
		writeAuthorizedResponse(resp)
		return
	}
	writeUnauthorizedResponse(resp)
	return
}

func unmarshallJSONRequest(req *http.Request) (*ReviewRequest, error) {
	reviewRequest := &ReviewRequest{}
	err := json.NewDecoder(req.Body).Decode(reviewRequest)
	if err != nil {
		return reviewRequest, err
	}

	return nil, nil
}

func isAuthorized(interface{}) bool {
	return true
}

func writeAuthorizedResponse(resp http.ResponseWriter) {
	// request is authorized
	status := ReviewStatus{
		Allowed: true,
	}
	writeCannedResponse(status, resp)
}

func writeUnauthorizedResponse(resp http.ResponseWriter) {
	status := ReviewStatus{
		Allowed: false,
		Reason:  "default denied authorization response",
	}
	writeCannedResponse(status, resp)
}

func writeCannedResponse(status ReviewStatus, resp http.ResponseWriter) {
	reviewResponse := ReviewResponse{
		APIVersion: "authorization.k8s.io/v1beta1",
		Kind:       "SubjectAccessReview",
		Status:     status,
	}

	respJSON, err := json.Marshal(reviewResponse)
	if err != nil {
		glog.Errorf("Error marshalling response: %v", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp.Header().Add("Content-Type", "application/json")
	resp.Write(respJSON)
}
