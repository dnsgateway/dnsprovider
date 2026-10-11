package delegation_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	dp "github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/delegation"
	"github.com/dnsgateway/dnsprovider/providers/porkbun"
)

func TestWorkflowRespectsPorkbunDigestSelectionAndBlocksExistingReplacement(t *testing.T) {
	for _, existing := range []bool{false, true} {
		w, _, ns, o := executionFixture()
		records := map[string]map[string]string{}
		if existing {
			records["123"] = map[string]string{"keyTag": "123", "alg": "13", "digestType": "1", "digest": "AABBCC"}
			o.parent.SigningKeys = []dp.SigningKey{{KeyTag: 123, DS: []string{"123 13 1 AABBCC"}}}
		}
		writes := 0
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/dns/getDnssecRecords/example.com":
				if err := json.NewEncoder(response).Encode(map[string]any{"status": "SUCCESS", "records": records}); err != nil {
					t.Error(err)
				}
			case "/dns/createDnssecRecord/example.com":
				writes++
				var record map[string]string
				if err := json.NewDecoder(request.Body).Decode(&record); err != nil {
					t.Error(err)
				}
				records[record["keyTag"]] = record
				o.parent.SigningKeys = []dp.SigningKey{{KeyTag: 123, DS: []string{"123 13 2 ABCDEF"}}}
				if err := json.NewEncoder(response).Encode(map[string]string{"status": "SUCCESS"}); err != nil {
					t.Error(err)
				}
			default:
				writes++
				t.Errorf("unsafe or unexpected registrar operation: %s", request.URL.Path)
				response.WriteHeader(http.StatusBadRequest)
			}
		}))
		registrar, err := porkbun.New(porkbun.Config{Key: "test", Secret: "secret"}, dp.WithBaseURL(server.URL))
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		w.Registrar = registrar
		desired := []dp.SigningKey{{KeyTag: 123, DNSKEY: "257 3 13 TEST", DS: []string{"123 13 1 AABBCC", "123 13 2 ABCDEF"}}}
		if existing {
			desired[0].DS = []string{"123 13 2 ABCDEF"}
		}
		p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, DS: delegation.PublishDS, SigningKeys: desired})
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		progress, err := w.Execute(context.Background(), p)
		server.Close()
		if existing {
			// Porkbun would replace this key tag by deleting SHA-1 before
			// adding SHA-256. Final trust alone cannot authorize that write.
			if err != delegation.ErrPending || writes != 0 || ns.writes != 0 || progress.Remaining[0].Code != delegation.UnsafeDNSSEC {
				t.Fatalf("existing Porkbun DS replacement accepted: %+v %v writes=%d/%d", progress, err, writes, ns.writes)
			}
		} else if err != nil || writes != 1 || ns.writes != 1 || len(progress.Remaining) != 0 {
			t.Fatalf("Porkbun selected digest not confirmed: %+v %v writes=%d/%d", progress, err, writes, ns.writes)
		}
	}
}
