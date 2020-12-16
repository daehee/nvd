package nvd

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
)

const (
	nvdCWEFeed = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
)

// FetchCWE fetches CWE archive
func (c *Client) FetchCWE() (cwes WeaknessCatalog, err error) {
	p := path.Join(c.feedDir, "cwe.xml.zip")
	exists := fileExists(p)
	if !exists {
		u := nvdCWEFeed
		resp, err := http.Get(u)
		if err != nil {
			return WeaknessCatalog{}, fmt.Errorf("error http request to %s: %v", u, err)
		}
		defer resp.Body.Close()

		f, err := os.Create(p)
		if err != nil {
			return WeaknessCatalog{}, fmt.Errorf("error creating file %s: %v", p, err)
		}
		defer f.Close()

		raw, _ := ioutil.ReadAll(resp.Body)
		f.Write(raw)
	}

	// Open and unzip file to WeaknessCatalog struct
	reader, err := zip.OpenReader(p)
	if err != nil {
		return WeaknessCatalog{}, fmt.Errorf("error unzipping %s: %v", p, err)
	}
	for _, f := range reader.File {
		src, err := f.Open()
		if err != nil {
			return cwes, err
		}

		b, err := ioutil.ReadAll(src)
		if err != nil {
			return WeaknessCatalog{}, fmt.Errorf("error reading file %s: %v", p, err)
		}
		src.Close()

		err = xml.Unmarshal(b, &cwes)
		if err != nil {
			return WeaknessCatalog{}, fmt.Errorf("error unmarshaling: %v", err)
		}
	}
	return cwes, nil
}
