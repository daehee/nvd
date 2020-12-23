package nvd

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// fetchReservedCVE scrapes CVE data from MITRE database when doesn't exist in NIST
// and if Reserved status at least mocks a CVE entry with shell description and a published date
func fetchReservedCVE(cveID string) (CVEItem, error) {
	var cve CVEItem
	cve.CVE.CVEDataMeta.ID = cveID

	var description, publishedDate string

	h := &http.Client{Timeout: 10 * time.Second}

	targetURL := fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", cveID)
	res, err := h.Get(targetURL)
	if err != nil {
		return cve, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return cve, fmt.Errorf("cve.mitre.org request error: %d %s", res.StatusCode, res.Status)
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return CVEItem{}, fmt.Errorf("error goquery parsing response body: %v", err)
	}

	// Description
	// #GeneratedTable > table > tbody > tr:nth-child(4) > td
	doc.Find("#GeneratedTable > table > tbody > tr:nth-child(4) > td").Each(func(i int, s *goquery.Selection) {
		description = s.Text()
	})

	// Published Date
	// #GeneratedTable > table > tbody > tr:nth-child(11) > td:nth-child(1) > b
	doc.Find("#GeneratedTable > table > tbody > tr:nth-child(11) > td:nth-child(1) > b").Each(func(i int, s *goquery.Selection) {
		publishedDate = s.Text()
	})

	// Process published date
	if publishedDate == "" {
		return CVEItem{}, errors.New("published date not found")
	}
	cve.PublishedDate, err = convertMitreToCVEDate(publishedDate)
	if err != nil {
		return CVEItem{}, fmt.Errorf("error converting MITRE published date: %v", err)
	}

	// Process description
	if strings.Contains(description, "** RESERVED **") {
		description = ""
		// Set Reserved flag to allow consumer to identify as such
		cve.Reserved = true
	} else {
		cve.CVE.Description.DescriptionData = append(cve.CVE.Description.DescriptionData,
			struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				Lang:  "en",
				Value: description,
			})
	}

	return cve, nil
}

func convertMitreToCVEDate(inDate string) (string, error) {
	layout := "20060102"
	parsedDate, err := time.Parse(layout, inDate)
	if err != nil {
		return "", err
	}
	return parsedDate.Format("2006-01-02T15:04Z"), nil
}
