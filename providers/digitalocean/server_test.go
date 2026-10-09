package digitalocean_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

// recordServer speaks the Domain Records API of one Domain, example.com:
// it pages lists by per_page, stores only the fields each type takes, and
// answers PUT with the whole stored Record. It refuses SOA deletion and a
// PUT changing a Record's type, as the safest reading of the API.
type recordServer struct {
	t       *testing.T
	records map[int]map[string]any
	next    int
	writes  []string
	bodies  []map[string]any
	// emptyAnswers makes POST and PUT acknowledge without a body.
	emptyAnswers bool
	failDelete   bool
	// domainReads counts the GETs of the Domain itself.
	domainReads int
}

func newRecords(t *testing.T) *recordServer {
	s := &recordServer{t: t, records: map[int]map[string]any{}, next: 28448500}
	s.records[28448441] = map[string]any{"id": 28448441, "type": "SOA", "name": "@", "data": "1800", "ttl": 1800}

	return s
}

// add stores a Record as the API would have, returning its ID.
func (s *recordServer) add(fields map[string]any) int {
	s.next++
	row := map[string]any{"id": s.next, "priority": nil, "port": nil, "weight": nil, "flags": nil, "tag": nil}
	maps.Copy(row, fields)
	s.records[s.next] = row

	return s.next
}

func (s *recordServer) fail(w http.ResponseWriter, status int, id, msg string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"id":%q,"message":%q,"request_id":"4d9d8375-3c56-4925-a3e7-eb137fed17e9"}`, id, msg)
}

func (s *recordServer) handler(w http.ResponseWriter, r *http.Request) {
	const base = "/v2/domains/example.com/records"
	switch {
	case r.URL.Path == "/v2/domains/example.com" && r.Method == http.MethodGet:
		s.domainReads++
		fmt.Fprintf(w, `{"domain":%s}`, domainJSON("example.com"))
		return
	case r.URL.Path == base && r.Method == http.MethodGet:
		s.list(w, r)
		return
	case r.URL.Path == base && r.Method == http.MethodPost:
		s.write(w, r, 0)
		return
	case !strings.HasPrefix(r.URL.Path, base+"/"):
		s.fail(w, http.StatusNotFound, "not_found", "The resource you were accessing could not be found.")
		return
	}
	id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, base+"/"))
	row, ok := s.records[id]
	if err != nil || !ok {
		s.fail(w, http.StatusNotFound, "not_found", "The resource you were accessing could not be found.")
		return
	}
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]any{"domain_record": row})
	case http.MethodPut:
		s.write(w, r, id)
	case http.MethodDelete:
		if s.failDelete || row["type"] == "SOA" {
			s.fail(w, http.StatusUnprocessableEntity, "unprocessable_entity", "Record cannot be deleted")
			return
		}
		delete(s.records, id)
		s.writes = append(s.writes, fmt.Sprintf("DELETE %d", id))
		w.WriteHeader(http.StatusNoContent)
	default:
		s.fail(w, http.StatusMethodNotAllowed, "method_not_allowed", "unexpected method")
	}
}

func (s *recordServer) list(w http.ResponseWriter, r *http.Request) {
	ids := make([]int, 0, len(s.records))
	for id, row := range s.records {
		if typ := r.URL.Query().Get("type"); typ == "" || row["type"] == typ {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	size, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if size < 1 || size > 200 || page < 1 {
		s.fail(w, http.StatusBadRequest, "bad_request", "invalid paging")
		return
	}
	rows := []map[string]any{}
	for i := (page - 1) * size; i < len(ids) && i < page*size; i++ {
		rows = append(rows, s.records[ids[i]])
	}
	links := map[string]any{}
	if page*size < len(ids) {
		links["pages"] = map[string]string{"next": fmt.Sprintf("https://api.digitalocean.com%s?page=%d&per_page=%d", r.URL.Path, page+1, size)}
	}
	json.NewEncoder(w).Encode(map[string]any{"domain_records": rows, "links": links, "meta": map[string]any{"total": len(ids)}})
}

// typeFields are the type-specific fields each type stores.
var typeFields = map[string][]string{
	"MX":  {"priority"},
	"SRV": {"priority", "weight", "port"},
	"CAA": {"flags", "tag"},
}

func (s *recordServer) write(w http.ResponseWriter, r *http.Request, id int) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.fail(w, http.StatusBadRequest, "bad_request", "malformed JSON")
		return
	}
	s.bodies = append(s.bodies, body)
	typ, _ := body["type"].(string)
	if _, ok := body["data"].(string); !ok || typ == "" {
		s.fail(w, http.StatusUnprocessableEntity, "unprocessable_entity", "type and data are required")
		return
	}
	if id != 0 && s.records[id]["type"] != typ {
		s.fail(w, http.StatusUnprocessableEntity, "unprocessable_entity", "type cannot be changed")
		return
	}
	data := body["data"].(string)
	if slices.Contains([]string{"CNAME", "NS", "MX", "SRV"}, typ) && data != "." {
		// The API answers host names without their trailing dot.
		data = strings.TrimSuffix(data, ".")
	}
	if tag, _ := body["tag"].(string); typ == "CAA" && tag != "iodef" {
		// As for host names, the API answers an issuer domain without the
		// trailing dot it is written with.
		data = strings.TrimSuffix(data, ".")
	}
	row := map[string]any{"type": typ, "name": body["name"], "data": data, "ttl": body["ttl"]}
	for _, f := range []string{"priority", "port", "weight", "flags", "tag"} {
		row[f] = nil
		if slices.Contains(typeFields[typ], f) {
			if body[f] == nil {
				s.fail(w, http.StatusUnprocessableEntity, "unprocessable_entity", f+" is required")
				return
			}
			row[f] = body[f]
		}
	}
	method := "PUT"
	if id == 0 {
		method = "POST"
		id = s.add(nil)
	}
	row["id"] = id
	s.records[id] = row
	s.writes = append(s.writes, fmt.Sprintf("%s %d", method, id))
	if method == "POST" {
		w.WriteHeader(http.StatusCreated)
	}
	if s.emptyAnswers {
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"domain_record": row})
}

var exampleZone = dnsprovider.Zone{ID: "example.com", Name: "example.com"}
