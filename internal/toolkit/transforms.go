// Package toolkit holds small, standalone data transforms used by the Tools
// section's encode/decode utility. Each transform maps a string to a string (or
// an error) and is free of any Profile, network, or database dependency.
package toolkit

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/beevik/etree"
)

// Transform is one named operation offered by the encode/decode tool.
type Transform struct {
	Key   string // stable identifier used in form values
	Label string // human label for the UI
	Group string // grouping for display (Base64, URL, DEFLATE, Format)
	Apply func(string) (string, error)
}

// Transforms is the ordered list of available operations.
var Transforms = []Transform{
	{"b64-encode", "Base64 encode", "Base64", func(s string) (string, error) {
		return base64.StdEncoding.EncodeToString([]byte(s)), nil
	}},
	{"b64-decode", "Base64 decode", "Base64", func(s string) (string, error) {
		return decodeBase64(s)
	}},
	{"b64url-encode", "Base64URL encode", "Base64", func(s string) (string, error) {
		return base64.RawURLEncoding.EncodeToString([]byte(s)), nil
	}},
	{"b64url-decode", "Base64URL decode", "Base64", func(s string) (string, error) {
		return decodeBase64(s)
	}},
	{"url-encode", "URL encode", "URL", func(s string) (string, error) {
		return url.QueryEscape(s), nil
	}},
	{"url-decode", "URL decode", "URL", func(s string) (string, error) {
		out, err := url.QueryUnescape(s)
		if err != nil {
			return "", err
		}
		return out, nil
	}},
	{"deflate", "DEFLATE + Base64", "DEFLATE", func(s string) (string, error) {
		return deflateBase64(s)
	}},
	{"inflate", "Base64 + INFLATE", "DEFLATE", func(s string) (string, error) {
		return inflateBase64(s)
	}},
	{"json-pretty", "Format JSON", "Format", func(s string) (string, error) {
		return prettyJSON(s)
	}},
	{"xml-pretty", "Format XML", "Format", func(s string) (string, error) {
		return prettyXML(s)
	}},
}

// Apply runs the transform identified by key against input.
func Apply(key, input string) (string, error) {
	for _, t := range Transforms {
		if t.Key == key {
			return t.Apply(input)
		}
	}
	return "", fmt.Errorf("unknown transform %q", key)
}

// decodeBase64 accepts standard and URL-safe base64, with or without padding.
func decodeBase64(s string) (string, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("not valid base64")
}

func deflateBase64(s string) (string, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := w.Write([]byte(s)); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func inflateBase64(s string) (string, error) {
	raw, err := decodeBase64(s)
	if err != nil {
		return "", err
	}
	r := flate.NewReader(strings.NewReader(raw))
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, 5<<20))
	if err != nil {
		return "", fmt.Errorf("inflate: %w", err)
	}
	return string(out), nil
}

func prettyJSON(s string) (string, error) {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func prettyXML(s string) (string, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(s); err != nil {
		return "", fmt.Errorf("invalid XML: %w", err)
	}
	doc.Indent(2)
	out, err := doc.WriteToString()
	if err != nil {
		return "", err
	}
	return out, nil
}
