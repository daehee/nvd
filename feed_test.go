package nvd

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClient_FetchCVE(t *testing.T) {
	tests := []struct {
		cveID           string
		wantReserved    bool
		wantErr         bool
		wantErrNotFound bool
	}{
		// success
		{"CVE-2019-5736", false, false, false},
		// success Reserved CVE
		{"CVE-2015-2231", true, false, false},
		// fail invalid CVE
		{"CVE-201900-5736", false, true, false},
		// fail old year
		{"CVE-2000-5736", false, true, false},
		// fail future year
		{"CVE-2025-5736", false, true, false},
		// fail with ErrNotFound
		{"CVE-2002-99999", false, true, true},
	}

	for _, tt := range tests {
		t.Logf("run subtest %s", tt.cveID)

		cl, err := NewClient("tmp")
		if err != nil {
			t.Fatal(err)
		}

		got, err := cl.FetchCVE(tt.cveID)
		if tt.wantErr {
			assert.Error(t, err)
			t.Logf("want error; got error: %s", err)
			if tt.wantErrNotFound {
				assert.ObjectsAreEqual(ErrNotFound, err)
			}
			teardown()
			continue
		} else {
			assert.NoError(t, err)
		}
		assert.Equal(t, tt.cveID, got.CVE.CVEDataMeta.ID)
		if tt.wantReserved {
			assert.True(t, got.Reserved)
		} else {
			assert.False(t, got.Reserved)
		}

		teardown()
	}

}

// go test -run=Bench -bench=. -benchtime=20s -benchmem ./pkg/nvd
func BenchmarkClient_SearchFeed(b *testing.B) {
	cl, err := NewClient("tmp")
	if err != nil {
		b.Fatal(err)
	}
	err = cl.downloadFeed(
		fmt.Sprintf(nvdDataFeeds, "2020"),
		cl.pathToFeed("2020"),
	)
	if err != nil {
		b.Fatal(err)
	}

	for n := 0; n < b.N; n++ {
		_, err := cl.searchFeed("2020", "CVE-2020-14882")
		if err != nil {
			b.Error(err)
		}
	}

	teardown()
}

func TestClient_SearchFeed(t *testing.T) {
	cl, err := NewClient("tmp")
	if err != nil {
		t.Fatal(err)
	}
	err = cl.downloadFeed(
		fmt.Sprintf(nvdDataFeeds, "2020"),
		cl.pathToFeed("2020"),
	)
	if err != nil {
		t.Fatal(err)
	}

	cveID := "CVE-2020-14882"
	got, err := cl.searchFeed("2020", cveID)
	if err != nil {
		assert.NoError(t, err)
	}
	assert.Equal(t, cveID, got.CVE.CVEDataMeta.ID)

	teardown()
}

func TestClient_NeedNVDUpdate(t *testing.T) {
	tests := []struct {
		want           bool
		year           string
		alreadyUpdated bool
		meta           string
	}{
		// needNVDUpdate true; stale meta sha256 hash
		{
			true,
			"2002",
			false,
			`lastModifiedDate:2020-01-11T05:13:47-05:00
size:19924894
zipSize:1408391
gzSize:1408255
sha256:qwertyuiop@[
`,
		},
		// needNVDUpdate false; meta file already up-to-date
		{
			false,
			"2003",
			true,
			"",
		},
	}

	for i, tt := range tests {
		t.Logf("run subtest %d", i+1)
		var err error

		cl, err := NewClient("tmp")
		if err != nil {
			t.Fatal(err)
		}

		if !tt.alreadyUpdated {
			err = cl.saveNVDMeta(tt.year, []byte(tt.meta))
			if err != nil {
				t.Fatal(err)
			}
		} else {
			_, err = cl.fetchRemoteMeta(tt.year)
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := cl.needNVDUpdate(tt.year)
		assert.NoError(t, err)
		if got != tt.want {
			t.Errorf("got %v != want %v; want %v", got, tt.want, tt.want)
		}
		teardown()
	}

}

func TestFetchReserved(t *testing.T) {
	tests := []struct {
		wantDate  string
		wantError bool
		cve       string
	}{
		// Full CVE
		{"2020-10-30T00:00Z", false, "CVE-2020-28002"},
		// Reserved CVE with only date & generic description
		{"2015-03-06T00:00Z", false, "CVE-2015-2231"},
		// Invalid CVE non-existent
		{"", true, "CVE-2020-28002999"},
	}
	for i, tt := range tests {
		t.Logf("run subtest %d", i+1)

		got, err := fetchReservedCVE(tt.cve)
		if tt.wantError {
			assert.Error(t, err)
			continue
		}
		assert.NoError(t, err)
		assert.Equal(t, tt.wantDate, got.PublishedDate)
	}
}

func teardown() {
	pwd := os.Getenv("PWD")
	d := path.Join(pwd, "tmp", "feeds")
	if _, err := os.Stat(d); !os.IsNotExist(err) {
		if err := os.RemoveAll(d); err != nil {
			fmt.Println(err)
		}
	}
}
