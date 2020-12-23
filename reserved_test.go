package nvd

import (
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
		got, err := fetchReservedCVE(tt.cveID)
		assert.NoError(t, err)
		assert.Equal(t, tt.cveID, got.CVE.CVEDataMeta.ID)
		assert.NotNil(t, got.PublishedDate)
		assert.True(t, got.Reserved)
		assert.Nil(t, got.CVE.Description.DescriptionData)
	}
}
