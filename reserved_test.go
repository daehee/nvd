package nvd

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFetchReservedCVE(t *testing.T) {
	tests := []struct {
		cveID string
	}{
		{"CVE-2020-27949"},
		{"CVE-2020-27190"},
	}

	for _, tt := range tests {
		cve, err := fetchReservedCVE(tt.cveID)
		assert.NoError(t, err)
		fmt.Printf("%+v\n\n", cve)
	}
}
