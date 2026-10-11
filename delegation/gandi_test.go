package delegation_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	dp "github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/delegation"
	"github.com/dnsgateway/dnsprovider/providers/gandi"
)

func TestWorkflowReconcilesGandiComputedDSForReviewedDNSKEY(t *testing.T) {
	const publicKey = "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="
	w, _, ns, initial := executionFixture()
	o := &recordingObserver{observer: initial}
	w.DNS = o
	keys := []map[string]any{}
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/domain/domains/example.com/dnskeys" {
			t.Errorf("unexpected path: %s", request.URL.Path)
			response.WriteHeader(http.StatusNotFound)
			return
		}
		switch request.Method {
		case http.MethodGet:
			page := keys
			if request.URL.Query().Get("page") != "1" {
				page = []map[string]any{}
			}
			if err := json.NewEncoder(response).Encode(page); err != nil {
				t.Error(err)
			}
		case http.MethodPut:
			writes++
			var body struct{ Keys []map[string]any }
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if len(body.Keys) != 1 || body.Keys[0]["public_key"] != publicKey {
				t.Errorf("unexpected reviewed DNSKEY: %+v", body)
			}
			keys = []map[string]any{{"id": 101, "type": "ksk", "algorithm": 13, "public_key": publicKey, "keytag": 2371, "digest_type": 2, "digest": "ABCDEF"}}
			o.parent.SigningKeys = []dp.SigningKey{{KeyTag: 2371, DS: []string{"2371 13 2 ABCDEF"}}}
			response.WriteHeader(http.StatusAccepted)
			if err := json.NewEncoder(response).Encode(map[string]string{"message": "The DNSSEC keys are being replaced."}); err != nil {
				t.Error(err)
			}
		default:
			t.Errorf("unexpected operation: %s", request.Method)
			response.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	registrar, err := gandi.New(gandi.Config{Token: "pat_test"}, dp.WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	w.Registrar = registrar
	p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, DS: delegation.PublishDS, SigningKeys: []dp.SigningKey{{DNSKEY: "257 3 13 " + publicKey}}})
	if err != nil {
		t.Fatal(err)
	}
	progress, err := w.Execute(context.Background(), p)
	if err != nil || writes != 1 || ns.writes != 1 || len(progress.Remaining) != 0 {
		t.Fatalf("computed Gandi DS not confirmed: %+v %v writes=%d/%d", progress, err, writes, ns.writes)
	}
	if len(o.lastKeys) != 1 || o.lastKeys[0].DNSKEY != "" || len(o.lastKeys[0].DS) != 1 || o.lastKeys[0].DS[0] != "2371 13 2 ABCDEF" {
		t.Fatalf("actual parent DS not verified: %+v", o.lastKeys)
	}
	_, err = w.Resume(context.Background(), progress)
	if err != nil || writes != 1 {
		t.Fatalf("accepted Gandi publication repeated: %v writes=%d", err, writes)
	}
}
