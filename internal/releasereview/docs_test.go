package releasereview

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// The doc's spec examples are what a consumer copies, so they are held to the
// validator rather than to review: an example the shipped build refuses is a
// defect in the contract, not a typo.
func TestDocumentedSpecExamplesValidate(t *testing.T) {
	const docPath = "../../docs/release-review.md"

	content, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}

	// A spec example is a block naming both a spec_version and a subject. The
	// doc also shows JSON that is not a spec — the capability advertisement
	// quotes the spec_version it promises — and holding that to the spec
	// validator would refuse a correct document.
	blocks := jsonBlocks(string(content))
	specs := make([]string, 0, len(blocks))
	for _, block := range blocks {
		if strings.Contains(block, `"spec_version"`) && strings.Contains(block, `"subject"`) {
			specs = append(specs, block)
		}
	}
	// Without this the test would pass silently forever if the fences were
	// renamed or the examples moved.
	if len(specs) == 0 {
		t.Fatalf("%s contains no ```json block with a spec_version — the examples are no longer covered", docPath)
	}

	for i, spec := range specs {
		if _, err := Decode(strings.NewReader(spec)); err != nil {
			t.Errorf("spec example %d in %s is refused by Decode: %v\n%s", i+1, docPath, err, spec)
		}
	}
}

func jsonBlocks(markdown string) []string {
	var blocks []string
	var current bytes.Buffer
	inBlock := false

	for _, line := range strings.Split(markdown, "\n") {
		switch {
		case !inBlock && strings.TrimSpace(line) == "```json":
			inBlock = true
			current.Reset()
		case inBlock && strings.TrimSpace(line) == "```":
			inBlock = false
			blocks = append(blocks, current.String())
		case inBlock:
			current.WriteString(line)
			current.WriteString("\n")
		}
	}
	return blocks
}
