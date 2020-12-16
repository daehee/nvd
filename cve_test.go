package nvd

import (
	"bufio"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseCVEID(t *testing.T) {
	tests := []struct {
		wantYear int
		wantSeq  int
		cveID    string
	}{
		{2020, 14882, "CVE-2020-14882"},
		{2014, 4294967296, "CVE-2014-4294967296"},
		{2014, 1, "CVE-2014-0001"},
		{2014, 99, "CVE-2014-0099"},
		{2014, 999, "CVE-2014-0999"},
	}

	for _, tt := range tests {
		gotYear, gotSeq := ParseCVEID(tt.cveID)
		assert.Equal(t, tt.wantYear, gotYear)
		assert.Equal(t, tt.wantSeq, gotSeq)
	}
}

func TestPadCVESequence(t *testing.T) {
	tests := []struct {
		want string
		seq  int
	}{
		{"0001", 1},
		{"0011", 11},
		{"0111", 111},
		{"1111", 1111},
		{"11111", 11111},
		{"111111", 111111},
	}

	for _, tt := range tests {
		got := PadCVESequence(tt.seq)
		assert.Equal(t, tt.want, got)
	}
}

func TestFixCVEID(t *testing.T) {
	tests := []struct {
		want  string
		cveID string
	}{
		{"CVE-2020-14882", "CVE-2020-0014882"},
		{"CVE-2020-14882", "CVE-2020-14882"},
	}

	for _, tt := range tests {
		got := FixCVEID(tt.cveID)
		assert.Equal(t, tt.want, got)
	}

}

func TestIsCVEIDStrict(t *testing.T) {
	validIDs, err := loadTestData("valid-syntax.out")
	if err != nil {
		t.Fatal(err)
	}
	for _, cveID := range validIDs {
		ok := IsCVEIDStrict(cveID)
		if !ok {
			t.Errorf("got invalid; want valid: %s", cveID)
		}
	}
	invalidIDs, err := loadTestData("invalid-syntax.out")
	if err != nil {
		t.Fatal(err)
	}
	for _, cveID := range invalidIDs {
		ok := IsCVEIDStrict(cveID)
		if ok {
			t.Errorf("got valid; want invalid: %s", cveID)
		}
	}
}

// TestIsCVEID should fail on the invalid IDs, matching some of them since based on Loose.
// Review these manually to check if acceptable range of match
func TestIsCVEID(t *testing.T) {
	validIDs, err := loadTestData("valid-syntax.out")
	if err != nil {
		t.Fatal(err)
	}
	for _, cveID := range validIDs {
		ok := IsCVEID(cveID)
		if !ok {
			t.Errorf("got invalid; want valid: %s", cveID)
		}
	}
	invalidIDs, err := loadTestData("invalid-syntax.out")
	if err != nil {
		t.Fatal(err)
	}
	for _, cveID := range invalidIDs {
		ok := IsCVEID(cveID)
		if ok {
			t.Errorf("got valid; want invalid: %s", cveID)
		}
	}
}

func loadTestData(fileName string) ([]string, error) {
	f, err := os.Open(path.Join("testdata", fileName))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
