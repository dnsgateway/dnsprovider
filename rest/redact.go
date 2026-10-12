package rest

import (
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/dnsgateway/dnsprovider"
)

// redacted replaces a secret in text Do and Redact hand back.
const redacted = "[redacted]"

// Redact is s with every one of the Client's Secrets replaced, as written
// and as escaped for a URL query or path, the escapes in either case. It
// is for text an adapter builds outside Do, such as an error answer read
// from a 2xx body.
func (c *Client) Redact(s string) string {
	return redactWith(c.secretPattern(), s)
}

// secretPattern matches any of the Client's Secrets in any of its
// forms, the longest first; nil when there are none.
func (c *Client) secretPattern() *regexp.Regexp {
	type form struct {
		text    string
		escaped bool
	}

	forms := make([]form, 0, 3*len(c.Secrets))

	for _, s := range c.Secrets {
		if s != "" {
			forms = append(forms, form{text: s}, form{text: url.QueryEscape(s), escaped: true}, form{text: url.PathEscape(s), escaped: true})
		}
	}

	if len(forms) == 0 {
		return nil
	}

	slices.SortStableFunc(forms, func(a, b form) int { return len(b.text) - len(a.text) })

	patterns := make([]string, 0, len(forms))

	for _, f := range forms {
		var b strings.Builder

		for i := 0; i < len(f.text); i++ {
			// A percent escape's hex digits may come back in either case.
			if f.escaped && f.text[i] == '%' && i+2 < len(f.text) {
				b.WriteString("(?i:")
				b.WriteString(regexp.QuoteMeta(f.text[i : i+3]))
				b.WriteString(")")
				i += 2

				continue
			}

			b.WriteString(regexp.QuoteMeta(f.text[i : i+1]))
		}

		patterns = append(patterns, b.String())
	}

	return regexp.MustCompile(strings.Join(patterns, "|"))
}

func redactWith(re *regexp.Regexp, s string) string {
	if re == nil {
		return s
	}

	return re.ReplaceAllString(s, redacted)
}

// RedactError is err with no Secret left in its text or in the text of
// any cause it exposes: an *APIError's Messages, a *url.Error's URL. It
// still matches what err matched with errors.Is. Do's errors need none;
// it is for errors an adapter makes outside Do.
func (c *Client) RedactError(err error) error {
	re := c.secretPattern()
	if err == nil || re == nil || secretFree(re, err) {
		return err
	}

	return cleanWith(re, err)
}

func cleanWith(re *regexp.Regexp, err error) error {
	if secretFree(re, err) {
		return err
	}

	if apiErr, ok := err.(*dnsprovider.APIError); ok {
		cp := *apiErr
		cp.Messages = make([]string, len(apiErr.Messages))

		for i, m := range apiErr.Messages {
			cp.Messages[i] = redactWith(re, m)
		}

		return &cp
	}

	if uerr, ok := err.(*url.Error); ok {
		cp := *uerr
		cp.URL, cp.Op = redactWith(re, cp.URL), redactWith(re, cp.Op)
		cp.Err = cleanWith(re, cp.Err)

		return &cp
	}

	text := redactWith(re, err.Error())

	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		causes := multi.Unwrap()
		safe := make([]error, len(causes))

		for i, cause := range causes {
			safe[i] = cleanWith(re, cause)
		}

		return &redactedError{text: text, cause: errors.Join(safe...), original: err}
	}

	if cause := errors.Unwrap(err); cause != nil {
		return &redactedError{text: text, cause: cleanWith(re, cause), original: err}
	}

	return &redactedError{text: text, original: err}
}

// secretFree reports whether no Secret shows in err's text or in any
// cause it exposes, including wrappers whose text hides their cause's.
func secretFree(re *regexp.Regexp, err error) bool {
	if err == nil {
		return true
	}

	if re.MatchString(err.Error()) {
		return false
	}

	if uerr, ok := err.(*url.Error); ok && (re.MatchString(uerr.URL) || re.MatchString(uerr.Op)) {
		return false
	}

	if apiErr, ok := err.(*dnsprovider.APIError); ok && slices.ContainsFunc(apiErr.Messages, re.MatchString) {
		return false
	}

	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		for _, cause := range multi.Unwrap() {
			if !secretFree(re, cause) {
				return false
			}
		}

		return true
	}

	return secretFree(re, errors.Unwrap(err))
}

// redactedError is an error whose text had a Secret in it. Its causes
// are cleaned too; errors.Is still sees the original chain.
type redactedError struct {
	text     string
	cause    error
	original error
}

func (e *redactedError) Error() string        { return e.text }
func (e *redactedError) Unwrap() error        { return e.cause }
func (e *redactedError) Is(target error) bool { return errors.Is(e.original, target) }
