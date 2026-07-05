package toolkit

import "testing"

func TestBase64RoundTrip(t *testing.T) {
	enc, err := Apply("b64-encode", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if enc != "aGVsbG8=" {
		t.Errorf("b64-encode = %q", enc)
	}
	dec, err := Apply("b64-decode", enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec != "hello" {
		t.Errorf("b64-decode = %q", dec)
	}
}

func TestDeflateInflateRoundTrip(t *testing.T) {
	const in = "<AuthnRequest>...</AuthnRequest>"
	comp, err := Apply("deflate", in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Apply("inflate", comp)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Errorf("round trip = %q, want %q", out, in)
	}
}

func TestURLEncodeDecode(t *testing.T) {
	enc, _ := Apply("url-encode", "a b&c")
	dec, err := Apply("url-decode", enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec != "a b&c" {
		t.Errorf("url round trip = %q", dec)
	}
}

func TestFormatJSON(t *testing.T) {
	out, err := Apply("json-pretty", `{"b":1,"a":2}`)
	if err != nil {
		t.Fatal(err)
	}
	if out == `{"b":1,"a":2}` {
		t.Error("expected indented JSON")
	}
	if _, err := Apply("json-pretty", "{not json"); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestFormatXML(t *testing.T) {
	out, err := Apply("xml-pretty", `<a><b>x</b></a>`)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) <= len(`<a><b>x</b></a>`) {
		t.Errorf("expected indented XML, got %q", out)
	}
}

func TestUnknownTransform(t *testing.T) {
	if _, err := Apply("nope", "x"); err == nil {
		t.Error("expected error for unknown transform")
	}
}
