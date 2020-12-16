package nvd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
)

// VendorsProducts parse CPEs and returns slice of Vendors containing Products
func (cve *CVEItem) VendorsProducts() []Vendor {
	// Get all Configuration.Nodes -> CPEMatch -> CPE23URI
	var cpeURIs []string
	for _, node := range cve.Configurations.Nodes {
		for _, cpe := range node.CPEMatch {
			cpeURIs = append(cpeURIs, cpe.CPE23URI)
		}
	}
	return generateVendorsProducts(cpeURIs)
}

// generateVendorProducts takes a slice of CPE strings and returns a slice of Vendors containing Products
func generateVendorsProducts(cpeURIs []string) []Vendor {
	// Build a staging map of vendors to urishorts,
	// where a map appends urishorts to unique vendors
	// 1. Loop each CPE23URI
	// 2. Split CPE23URI into vendor and urishort
	// 3. Append urishort to its vendor key
	tmp := make(map[string][]string) // temporary staging map
	for _, uri := range cpeURIs {
		vendor, urishort := splitCPE(uri)
		// If vendor key doesn't exist, initialize new slice wit urishort
		tmpURIs, exists := tmp[vendor]
		if !exists {
			tmp[vendor] = []string{urishort}
			continue
		}

		// Append urishort if not already exists in vendor key
		seen := false
		for _, tmpURI := range tmpURIs {
			if tmpURI == urishort {
				seen = true
				break
			}
		}
		if !seen {
			tmp[vendor] = append(tmp[vendor], urishort)
		}
	}

	// Convert staging map to Vendors slice with each Vendor containing Products slice
	var vendors []Vendor
	for tmpVendor, tmpURIs := range tmp {
		// Build Products slice
		var products []Product
		for _, u := range tmpURIs {
			products = append(products, urishortToProduct(u))
		}
		// Build Vendor
		vendors = append(vendors, Vendor{
			// Name:     strings.Title(strings.Join(strings.Split(tmpVendor, "-"), " ")),
			// TODO splitmulti on vendor name with -_ separators
			Name:     strings.Title(tmpVendor),
			Products: products,
		})
	}
	return vendors
}

func urishortToProduct(urishort string) Product {
	splitMulti := func(s string, seps string) []string {
		splitter := func(r rune) bool {
			return strings.ContainsRune(seps, r)
		}
		return strings.FieldsFunc(s, splitter)
	}

	productStr := strings.Split(urishort, ":")[1]
	return Product{
		Name:     strings.Title(strings.Join(splitMulti(productStr, "-_"), " ")),
		URIShort: urishort,
	}
}

func splitCPE(cpe23URI string) (vendor, urishort string) {
	split := strings.Split(cpe23URI, ":")
	vendor = split[3]
	urishort = strings.Join([]string{split[3], split[4]}, ":")
	return
}

// FetchCPEMatches downloads cpematch feed from NVD (if not exist),
// and returns slice of cpe23Uri's
// Currently set to private method as test data only
func (c *Client) fetchCPEMatches() (CPEMatchFeed, error) {
	p := path.Join(c.feedDir, "cpematch.json")
	// TODO check if file exists
	if _, err := os.Stat(p); os.IsNotExist(err) {
		err := c.downloadFeed(nvdCPEMatchFeed, p)
		if err != nil {
			return CPEMatchFeed{}, err
		}
	}

	raw, err := ioutil.ReadFile(p)
	if err != nil {
		return CPEMatchFeed{}, fmt.Errorf("error reading local feed file %s: %v", p, err)
	}

	var cpes CPEMatchFeed
	err = json.Unmarshal(raw, &cpes)
	if err != nil {
		return CPEMatchFeed{}, errors.New("error unmarshaling cpe match feed")
	}

	return cpes, nil
}
