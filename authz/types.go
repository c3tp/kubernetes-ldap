package authz

// ReviewResponse is return value for webhook authorization request from k8s.
type ReviewResponse struct {
	Kind       string       `json:"kind"`
	APIVersion string       `json:"apiVersion"`
	Status     ReviewStatus `json:"status"`
}

// ReviewStatus is the the result of the authorization request.
type ReviewStatus struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// ReviewRequest is the request body from k8s for webhook authorization.
type ReviewRequest struct {
	Kind       string      `json:"kind"`
	APIVersion string      `json:"apiVersion"`
	Status     RequestSpec `json:"spec"`
}

// RequestSpec is the information to verify whether a user is allowed to access
type RequestSpec struct {
	ResourceAttributes ResourceAttributes
	User               string   `json:"user"`
	Group              []string `json:"group"`
}

// ResourceAttributes is the k8s request type.
type ResourceAttributes struct {
	Namespace string `json:"namespace"`
	Verb      string `json:"verb"`
	Group     string `json:"group"`
	Resource  string `json:"resource"`
}
