package vultr_test

import (
	"encoding/base64"
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

// recordServer speaks the DNS Records API of one DNS Domain, example.com,
// as the API reference, the official client and observed service rules
// describe it: lists are paged by per_page (at most 500) and an opaque
// cursor; POST answers 201 with the stored Record; PATCH answers 204 with
// no body; DELETE answers 204. priority is required for MX and SRV, TXT
// data must be enclosed in quotes with none inside, the Records of one
// name and type must share a TTL, and PATCH cannot change the type.
type recordServer struct {
	t *testing.T
	// order holds the IDs in creation order, as lists answer them.
	order   []string
	records map[string]map[string]any
	next    int
	writes  []string
	bodies  []map[string]any
	// malformedCreate makes POST acknowledge with a body that is not a
	// well-formed Record.
	malformedCreate string
	failDelete      bool
}

func newRecords(t *testing.T) *recordServer {
	return &recordServer{t: t, records: map[string]map[string]any{}}
}

func recordID(n int) string { return fmt.Sprintf("cb676a46-66fd-4dfb-b839-%012d", n) }

// add stores a Record as the API would have, returning its ID.
func (s *recordServer) add(fields map[string]any) string {
	s.next++
	id := recordID(s.next)
	row := map[string]any{"id": id, "priority": 0}
	maps.Copy(row, fields)
	s.records[id] = row
	s.order = append(s.order, id)

	return id
}

func (s *recordServer) fail(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q,"status":%d}`, msg, status)
}

func (s *recordServer) handler(w http.ResponseWriter, r *http.Request) {
	const base = "/v2/domains/example.com/records"
	switch {
	case r.URL.Path == base && r.Method == http.MethodGet:
		s.list(w, r)
		return
	case r.URL.Path == base && r.Method == http.MethodPost:
		s.create(w, r)
		return
	case !strings.HasPrefix(r.URL.Path, base+"/"):
		s.fail(w, http.StatusNotFound, "Domain not found.")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, base+"/")
	row, ok := s.records[id]
	if !ok {
		s.fail(w, http.StatusNotFound, "Record not found.")
		return
	}
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]any{"record": row})
	case http.MethodPatch:
		s.patch(w, r, id)
	case http.MethodDelete:
		if s.failDelete {
			s.fail(w, http.StatusBadRequest, "Unable to delete record.")
			return
		}
		delete(s.records, id)
		s.order = slices.DeleteFunc(s.order, func(v string) bool { return v == id })
		s.writes = append(s.writes, "DELETE "+id)
		w.WriteHeader(http.StatusNoContent)
	default:
		s.fail(w, http.StatusMethodNotAllowed, "unexpected method")
	}
}

func (s *recordServer) list(w http.ResponseWriter, r *http.Request) {
	size, err := strconv.Atoi(r.URL.Query().Get("per_page"))
	if err != nil || size < 1 || size > 500 {
		s.fail(w, http.StatusBadRequest, "Invalid per_page.")
		return
	}
	start := 0
	if c := r.URL.Query().Get("cursor"); c != "" {
		raw, err := base64.StdEncoding.DecodeString(c)
		if err != nil || !strings.HasPrefix(string(raw), "next__") {
			s.fail(w, http.StatusBadRequest, "Invalid cursor.")
			return
		}
		start, _ = strconv.Atoi(strings.TrimPrefix(string(raw), "next__"))
	}
	rows := []map[string]any{}
	for i := start; i < len(s.order) && i < start+size; i++ {
		rows = append(rows, s.records[s.order[i]])
	}
	next := ""
	if start+size < len(s.order) {
		next = base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "next__%d", start+size))
	}
	json.NewEncoder(w).Encode(map[string]any{"records": rows, "meta": map[string]any{"total": len(s.order), "links": map[string]string{"next": next, "prev": ""}}})
}

// check enforces the service's rules on a Record as it would be stored.
func (s *recordServer) check(row map[string]any, id string) (int, string) {
	typ, _ := row["type"].(string)
	data, ok := row["data"].(string)
	if !ok || typ == "" {
		return http.StatusBadRequest, "Missing required parameter: data"
	}
	if typ == "TXT" && (len(data) < 2 || !strings.HasPrefix(data, `"`) || !strings.HasSuffix(data, `"`)) {
		return http.StatusBadRequest, "Record data must be enclosed in quotes"
	}
	if typ == "TXT" && strings.Contains(data[1:len(data)-1], `"`) {
		return http.StatusBadRequest, "Quotes may only appear at the beginning and end of the data"
	}
	if (typ == "MX" || typ == "SRV") && row["priority"] == nil {
		return http.StatusBadRequest, "Missing required parameter: priority"
	}
	for other, o := range s.records {
		if other != id && o["type"] == typ && strings.EqualFold(o["name"].(string), row["name"].(string)) && fmt.Sprint(o["ttl"]) != fmt.Sprint(row["ttl"]) {
			return http.StatusBadRequest, "All records with the same name and type must have the same TTL"
		}
	}
	return 0, ""
}

func (s *recordServer) decode(w http.ResponseWriter, r *http.Request) map[string]any {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.fail(w, http.StatusBadRequest, "Invalid JSON.")
		return nil
	}
	s.bodies = append(s.bodies, body)
	return body
}

func (s *recordServer) create(w http.ResponseWriter, r *http.Request) {
	body := s.decode(w, r)
	if body == nil {
		return
	}
	if _, ok := body["name"].(string); !ok {
		s.fail(w, http.StatusBadRequest, "Missing required parameter: name")
		return
	}
	row := map[string]any{"type": body["type"], "name": body["name"], "data": body["data"], "ttl": body["ttl"], "priority": body["priority"]}
	if row["ttl"] == nil {
		row["ttl"] = 300.0
	}
	if code, msg := s.check(row, ""); code != 0 {
		s.fail(w, code, msg)
		return
	}
	if row["priority"] == nil {
		row["priority"] = 0
	}
	id := s.add(row)
	s.writes = append(s.writes, "POST "+id)
	w.WriteHeader(http.StatusCreated)
	if s.malformedCreate != "" {
		fmt.Fprint(w, s.malformedCreate)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"record": s.records[id]})
}

func (s *recordServer) patch(w http.ResponseWriter, r *http.Request, id string) {
	body := s.decode(w, r)
	if body == nil {
		return
	}
	row := maps.Clone(s.records[id])
	if t, ok := body["type"]; ok && t != row["type"] {
		s.fail(w, http.StatusBadRequest, "Record type cannot be changed")
		return
	}
	for _, k := range []string{"name", "data", "ttl", "priority"} {
		if v, ok := body[k]; ok {
			row[k] = v
		}
	}
	if code, msg := s.check(row, id); code != 0 {
		s.fail(w, code, msg)
		return
	}
	s.records[id] = row
	s.writes = append(s.writes, "PATCH "+id)
	w.WriteHeader(http.StatusNoContent)
}

var exampleZone = dnsprovider.Zone{ID: "example.com", Name: "example.com"}
