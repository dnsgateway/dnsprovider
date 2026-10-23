package inwx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strconv"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/rest"
)

// DomRobot result codes the adapter acts on, from the result code table
// of INWX's API documentation.
const (
	codeSuccess         = 1000
	codeRefusals        = 2000 // the first refusal code: every code from here on is one
	codeAuthentication  = 2200
	codeAuthorization   = 2201
	codeInvalidAuthInfo = 2202
	codeObjectExists    = 2302
	codeNoSuchObject    = 2303
	codeSessionLimit    = 2502
)

// envelope is a DomRobot answer: its result code, message, the reason
// for a refusal and the result data.
type envelope struct {
	Code       wireInt         `json:"code"`
	Msg        string          `json:"msg"`
	Reason     string          `json:"reason"`
	ReasonCode string          `json:"reasonCode"`
	ResData    json.RawMessage `json:"resData"`
}

// kind is the typed Provider error of a refusal code; nil for one
// that stays a plain APIError.
func kind(code wireInt) error {
	switch code {
	case codeAuthentication, codeAuthorization, codeInvalidAuthInfo:
		return dnsprovider.ErrUnauthorized
	case codeObjectExists:
		return dnsprovider.ErrConflict
	case codeNoSuchObject:
		return dnsprovider.ErrNotFound
	case codeSessionLimit:
		return dnsprovider.ErrRateLimited
	}

	return nil
}

// apiError is a refusal as an APIError of status 0, whose Messages
// carry the code, msg and reason.
func (e envelope) apiError() *dnsprovider.APIError {
	msgs := []string{fmt.Sprintf("%d %s", e.Code, e.Msg)}

	switch {
	case e.Reason != "" && e.ReasonCode != "":
		msgs = append(msgs, fmt.Sprintf("%s (%s)", e.Reason, e.ReasonCode))
	case e.Reason != "":
		msgs = append(msgs, e.Reason)
	case e.ReasonCode != "":
		msgs = append(msgs, e.ReasonCode)
	}

	return &dnsprovider.APIError{Provider: "inwx", Messages: msgs, Kind: kind(e.Code)}
}

// httpError is a non-2xx answer as an APIError of its status, with the
// DomRobot code and message when its body has them. HTTP 429 is
// ErrRateLimited by its status.
func httpError(res *http.Response, body []byte) error {
	e := &dnsprovider.APIError{Provider: "inwx", StatusCode: res.StatusCode}

	var env envelope
	if json.Unmarshal(body, &env) == nil && env.Code != 0 {
		e.Messages = env.apiError().Messages
	}

	return e
}

// errMalformed is an answer that cannot be decoded or has no code.
var errMalformed = errors.New("malformed answer")

// post is how a call goes out: rest.Client's Do for a read, its Write
// for a write.
type post func(ctx context.Context, method, path string, q url.Values, body, out any) error

// exchange sends one DomRobot call through send, as a POST of
// {"method", "params"} with lang "en" to the endpoint, and decodes its
// answer, whatever its code. An error of send is returned as it is; an
// answer that cannot be decoded or has no code is errMalformed. The
// caller classifies the code.
func exchange(ctx context.Context, send post, method string, params map[string]any) (envelope, error) {
	ps := maps.Clone(params)
	if ps == nil {
		ps = map[string]any{}
	}

	ps["lang"] = "en"

	var raw []byte
	if err := send(ctx, http.MethodPost, "", nil, map[string]any{"method": method, "params": ps}, &raw); err != nil {
		return envelope{}, err
	}

	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Code == 0 {
		return envelope{}, fmt.Errorf("inwx: %s: %w", method, errMalformed)
	}

	return env, nil
}

// rpc sends one call that changes nothing through c and decodes its
// answer. A refusal (a code of 2000 or more) is an APIError of status 0;
// any code below is success, including 1001 (pending) and 1500 (ending
// session), which the caller reads from the envelope where it matters.
func (p *Provider) rpc(ctx context.Context, c *rest.Client, method string, params map[string]any) (envelope, error) {
	env, err := exchange(ctx, c.Do, method, params)
	if err != nil {
		return envelope{}, err
	}

	if env.Code >= codeRefusals {
		return envelope{}, c.RedactError(env.apiError())
	}

	return env, nil
}

// read sends a call that changes nothing, with the session, and decodes
// its resData into out unless out is nil.
func (p *Provider) read(ctx context.Context, method string, params map[string]any, out any) error {
	env, err := p.send(ctx, func(c *rest.Client) (envelope, error) {
		return p.rpc(ctx, c, method, params)
	})
	if err != nil {
		return err
	}

	if out != nil {
		if err := decode(env.ResData, out); err != nil {
			return fmt.Errorf("inwx: %s: malformed resData: %w", method, err)
		}
	}

	return nil
}

// decode decodes resData into out; a missing resData is an error.
func decode(data json.RawMessage, out any) error {
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return errors.New("missing")
	}

	return json.Unmarshal(data, out)
}

// wireInt is a DomRobot integer, which may come as a JSON number or as a
// string holding one: the documentation's types and the clients
// disagree on several fields, such as count and id.
type wireInt int64

func (n *wireInt) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == "null" {
		return nil
	}

	if unq, err := strconv.Unquote(s); err == nil {
		s = unq
	}

	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("not an integer: %s", b)
	}

	*n = wireInt(v)

	return nil
}

func (n wireInt) String() string {
	return strconv.FormatInt(int64(n), 10)
}
