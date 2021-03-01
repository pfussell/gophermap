package parser

import (
	"bytes"
	"testing"
)

func TestNmapPrettyPrintBadInputPath(t *testing.T) {
	buffer := &bytes.Buffer{}
	p := New("../test/testfiles/doesnotexist", buffer)
	err := p.NmapPrettyPrint()

	if err == nil {
		t.Fatalf("Expected error with invalid file path")
	}
}
