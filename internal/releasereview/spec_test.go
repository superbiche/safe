package releasereview

import (
	"strings"
	"testing"
)

func TestDecodeRejects(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		wantSub string
	}{
		{
			name:    "unknown top-level field",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a"}],"extra":1}`,
			wantSub: `unknown field "extra"`,
		},
		{
			name:    "unknown nested field",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a","sha":"x"}]}`,
			wantSub: `unknown field "sha"`,
		},
		{
			name:    "unknown field inside a check block",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a"}],"checks":{"checksum":{"enabled":true,"strict":true}}}`,
			wantSub: `unknown field "strict"`,
		},
		{
			name:    "wrong spec_version",
			spec:    `{"spec_version":2,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a"}]}`,
			wantSub: "spec_version must be 1 (got 2)",
		},
		{
			name:    "missing spec_version",
			spec:    `{"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a"}]}`,
			wantSub: "spec_version must be 1 (got 0)",
		},
		{
			name:    "missing repo",
			spec:    `{"spec_version":1,"subject":{"version":"v1"},"artifacts":[{"path":"a"}]}`,
			wantSub: "subject.repo is required",
		},
		{
			name:    "missing version",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r"},"artifacts":[{"path":"a"}]}`,
			wantSub: "subject.version is required",
		},
		{
			name:    "no artifacts",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[]}`,
			wantSub: "artifacts must contain at least one entry",
		},
		{
			name:    "artifact without a path",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"asset_name":"a"}]}`,
			wantSub: "artifacts[0].path is required",
		},
		{
			name:    "signature with both identity forms",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a","evidence":{"signature":{"bundle":"b","identity":"i","identity_regexp":"r","oidc_issuer":"u"}}}]}`,
			wantSub: "identity and identity_regexp are mutually exclusive",
		},
		{
			name:    "signature with neither identity form",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a","evidence":{"signature":{"bundle":"b","oidc_issuer":"u"}}}]}`,
			wantSub: "one of identity or identity_regexp is required",
		},
		{
			name:    "signature without an issuer",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a","evidence":{"signature":{"bundle":"b","identity":"i"}}}]}`,
			wantSub: "signature.oidc_issuer is required",
		},
		{
			name:    "signature without a bundle",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a","evidence":{"signature":{"identity":"i","oidc_issuer":"u"}}}]}`,
			wantSub: "signature.bundle is required",
		},
		{
			name:    "unimplemented check enabled",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a","evidence":{"checksum_file":"c"}}],"checks":{"checksum":{"enabled":true},"signature":{"enabled":true}}}`,
			wantSub: `check "signature" is not implemented by this build (implements: checksum)`,
		},
		{
			name:    "unimplemented exec check enabled",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a"}],"checks":{"exec":{"enabled":true,"artifact":"a","timeout_seconds":5}}}`,
			wantSub: `check "exec" is not implemented by this build`,
		},
		{
			name:    "unimplemented tuf check enabled",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a"}],"checks":{"tuf":{"enabled":true,"mirror":"m","root":"r","root_checksum":"s","targets":{"n":"p"}}}}`,
			wantSub: `check "tuf" is not implemented by this build`,
		},
		{
			name:    "no checks enabled",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a"}],"checks":{}}`,
			wantSub: "no checks are enabled",
		},
		{
			name:    "every check explicitly disabled",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a"}],"checks":{"checksum":{"enabled":false},"vuln":{"enabled":false}}}`,
			wantSub: "no checks are enabled",
		},
		{
			name:    "checksum enabled with no checksum evidence anywhere",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a"},{"path":"b"}],"checks":{"checksum":{"enabled":true}}}`,
			wantSub: `check "checksum" is enabled but no artifact carries evidence.checksum_file`,
		},
		{
			name:    "default checks with no checksum evidence anywhere",
			spec:    `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a"}]}`,
			wantSub: `check "checksum" is enabled but no artifact carries evidence.checksum_file`,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(testCase.spec))
			if err == nil {
				t.Fatalf("expected a refusal, got none")
			}
			if !strings.Contains(err.Error(), testCase.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), testCase.wantSub)
			}
		})
	}
}

// F3: a decoder that reads one document and stops would accept anything
// appended to a spec, and would silently keep the last of two contradictory
// members. Both shapes mean the document does not say one thing.
func TestDecodeRejectsAmbiguousDocuments(t *testing.T) {
	const valid = `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},
	                "artifacts":[{"path":"a","evidence":{"checksum_file":"c"}}]}`

	cases := []struct {
		name    string
		spec    string
		wantSub string
	}{
		{"trailing object", valid + `{"unknown":true}`, "exactly one JSON document"},
		{"trailing scalar", valid + ` 7`, "exactly one JSON document"},
		{"trailing garbage", valid + " not json", "exactly one JSON document"},
		{"two whole specs", valid + valid, "exactly one JSON document"},
		{
			name: "contradictory spec_version",
			spec: `{"spec_version":2,"subject":{"repo":"o/r","version":"v1"},
			        "artifacts":[{"path":"a","evidence":{"checksum_file":"c"}}],"spec_version":1}`,
			wantSub: `"spec_version" is given more than once`,
		},
		{
			name: "repeated member inside subject",
			spec: `{"spec_version":1,"subject":{"repo":"o/r","repo":"other/r","version":"v1"},
			        "artifacts":[{"path":"a","evidence":{"checksum_file":"c"}}]}`,
			wantSub: `"subject.repo" is given more than once`,
		},
		{
			name: "repeated member inside an array element",
			spec: `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},
			        "artifacts":[{"path":"a","path":"b","evidence":{"checksum_file":"c"}}]}`,
			wantSub: `"artifacts.path" is given more than once`,
		},
		{
			name: "repeated member inside a check block",
			spec: `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},
			        "artifacts":[{"path":"a","evidence":{"checksum_file":"c"}}],
			        "checks":{"checksum":{"enabled":true,"enabled":false}}}`,
			wantSub: `"checks.checksum.enabled" is given more than once`,
		},
		{
			name: "repeated check block",
			spec: `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},
			        "artifacts":[{"path":"a","evidence":{"checksum_file":"c"}}],
			        "checks":{"checksum":{"enabled":true},"checksum":{"enabled":false}}}`,
			wantSub: `"checks.checksum" is given more than once`,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(testCase.spec))
			if err == nil {
				t.Fatalf("expected a refusal, got none")
			}
			if !strings.Contains(err.Error(), testCase.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), testCase.wantSub)
			}
		})
	}
}

// The single-document gate must not trip on the trailing newline every spec
// file on disk ends with, nor on surrounding whitespace.
func TestDecodeAcceptsSurroundingWhitespace(t *testing.T) {
	const valid = `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},
	                "artifacts":[{"path":"a","evidence":{"checksum_file":"c"}}]}`

	for _, spec := range []string{valid + "\n", valid + "\n\n", "\n\t" + valid + "  \n", valid} {
		if _, err := Decode(strings.NewReader(spec)); err != nil {
			t.Fatalf("unexpected refusal for %q: %v", spec, err)
		}
	}
}

// Deeply nested but duplicate-free documents pass the walk unharmed.
func TestDecodeAcceptsNestedDuplicateFreeSpec(t *testing.T) {
	spec := `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},
	          "artifacts":[
	            {"path":"a","asset_name":"a","evidence":{"checksum_file":"c",
	              "signature":{"bundle":"b","identity":"i","oidc_issuer":"u"}}},
	            {"path":"b","evidence":{"checksum_file":"c"}}],
	          "checks":{"checksum":{"enabled":true,"advisory":false}}}`
	if _, err := Decode(strings.NewReader(spec)); err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

// The unimplemented-check refusal names the first such check in report order,
// so the stderr line does not depend on JSON key order.
func TestUnimplementedRefusalIsDeterministic(t *testing.T) {
	spec := `{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a"}],
	          "checks":{"exec":{"enabled":true},"vuln":{"enabled":true},"signature":{"enabled":true}}}`
	_, err := Decode(strings.NewReader(spec))
	if err == nil {
		t.Fatal("expected a refusal, got none")
	}
	if !strings.Contains(err.Error(), `check "signature"`) {
		t.Fatalf("expected the refusal to name signature, got %q", err.Error())
	}
}

func TestDecodeDefaults(t *testing.T) {
	spec, err := Decode(strings.NewReader(
		`{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},
		  "artifacts":[{"path":"dist/foo.tar.gz","evidence":{"checksum_file":"dist/checksums.txt"}}]}`))
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}

	if got := spec.Artifacts[0].AssetName; got != "foo.tar.gz" {
		t.Fatalf("asset_name defaulted to %q, want foo.tar.gz", got)
	}

	enabled := spec.enabledChecks()
	if len(enabled) != 1 || enabled[0].ID != CheckChecksum || enabled[0].Advisory {
		t.Fatalf("omitted checks resolved to %+v, want checksum only, non-advisory", enabled)
	}
}

func TestExplicitAssetNameWins(t *testing.T) {
	spec, err := Decode(strings.NewReader(
		`{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},
		  "artifacts":[{"path":"dist/foo.tar.gz","asset_name":"foo-linux.tar.gz","evidence":{"checksum_file":"c"}}]}`))
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if got := spec.Artifacts[0].AssetName; got != "foo-linux.tar.gz" {
		t.Fatalf("asset_name is %q, want foo-linux.tar.gz", got)
	}
}

func TestEnabledChecksKeepReportOrder(t *testing.T) {
	spec := Spec{Checks: &Checks{
		Vuln:      &CheckConfig{Enabled: true, Advisory: true},
		Checksum:  &CheckConfig{Enabled: true},
		Signature: &CheckConfig{Enabled: true},
		Exec:      &ExecCheck{CheckConfig: CheckConfig{Enabled: true}},
	}}

	var ids []string
	for _, check := range spec.enabledChecks() {
		ids = append(ids, check.ID)
	}
	want := []string{CheckChecksum, CheckSignature, CheckVuln, CheckExec}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("enabled checks %v, want %v", ids, want)
	}
}

func TestAdvisoryMarkingSurvivesDecode(t *testing.T) {
	spec, err := Decode(strings.NewReader(
		`{"spec_version":1,"subject":{"repo":"o/r","version":"v1"},
		  "artifacts":[{"path":"a","evidence":{"checksum_file":"c"}}],
		  "checks":{"checksum":{"enabled":true,"advisory":true}}}`))
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	enabled := spec.enabledChecks()
	if len(enabled) != 1 || !enabled[0].Advisory {
		t.Fatalf("advisory marking lost: %+v", enabled)
	}
}
