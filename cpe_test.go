package nvd

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCVEItem_VendorsProducts(t *testing.T) {
	tests := []struct {
		cveBlob string
		want    []Vendor
	}{
		{`
{"cve": {"data_type": "CVE", "references": {"reference_data": [{"url": "https://www.cloudfoundry.org/blog/cve-2020-5417", "name": "https://www.cloudfoundry.org/blog/cve-2020-5417", "tags": ["Vendor Advisory"], "refsource": "CONFIRM"}]}, "data_format": "MITRE", "description": {"description_data": [{"lang": "en", "value": "Cloud Foundry CAPI (Cloud Controller), versions prior to 1.97.0, when used in a deployment where an app domain is also the system domain (which is true in the default CF Deployment manifest), were vulnerable to developers maliciously or accidentally claiming certain sensitive routes, potentially resulting in the developer's app handling some requests that were expected to go to certain system components."}]}, "problemtype": {"problemtype_data": [{"description": [{"lang": "en", "value": "CWE-732"}]}]}, "data_version": "4.0", "CVE_data_meta": {"ID": "CVE-2020-5417", "ASSIGNER": "cve@mitre.org"}}, "impact": {"baseMetricV2": {"cvssV2": {"version": "2.0", "baseScore": 6.5, "accessVector": "NETWORK", "vectorString": "AV:N/AC:L/Au:S/C:P/I:P/A:P", "authentication": "SINGLE", "integrityImpact": "PARTIAL", "accessComplexity": "LOW", "availabilityImpact": "PARTIAL", "confidentialityImpact": "PARTIAL"}, "severity": "MEDIUM", "acInsufInfo": false, "impactScore": 6.4, "obtainAllPrivilege": false, "exploitabilityScore": 8, "obtainUserPrivilege": false, "obtainOtherPrivilege": false, "userInteractionRequired": false}, "baseMetricV3": {"cvssV3": {"scope": "UNCHANGED", "version": "3.1", "baseScore": 8.8, "attackVector": "NETWORK", "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "integrityImpact": "HIGH", "userInteraction": "NONE", "attackComplexity": "LOW", "availabilityImpact": "HIGH", "privilegesRequired": "LOW", "confidentialityImpact": "HIGH"}, "impactScore": 5.9, "exploitabilityScore": 2.8}}, "publishedDate": "2020-08-21T22:15Z", "configurations": {"nodes": [{"operator": "OR", "cpe_match": [{"cpe23Uri": "cpe:2.3:a:cloudfoundry:cf-deployment:*:*:*:*:*:*:*:*", "vulnerable": true}, {"cpe23Uri": "cpe:2.3:a:cloudfoundry:cloud_controller:*:*:*:*:*:*:*:*", "vulnerable": true}]}], "CVE_data_version": "4.0"}, "lastModifiedDate": "2020-08-27T16:28Z"}
`, []Vendor{
			{
				Name: "Cloudfoundry",
				Products: []Product{
					{
						Name:     "Cf Deployment",
						URIShort: "cloudfoundry:cf-deployment",
					},
					{
						Name:     "Cloud Controller",
						URIShort: "cloudfoundry:cloud_controller",
					},
				},
			},
		}},
		{`
{"cve": {"data_type": "CVE", "references": {"reference_data": [{"url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/159229", "name": "ibm-infosphere-cve20194220-info-disc (159229)", "tags": ["VDB Entry", "Vendor Advisory"], "refsource": "XF"}, {"url": "https://www.ibm.com/support/docview.wss?uid=ibm10881197", "name": "https://www.ibm.com/support/docview.wss?uid=ibm10881197", "tags": ["Mitigation", "Vendor Advisory"], "refsource": "CONFIRM"}]}, "data_format": "MITRE", "description": {"description_data": [{"lang": "en", "value": "IBM InfoSphere Information Server 11.7.1.0 stores a common hard coded encryption key that could be used to decrypt sensitive information. IBM X-Force ID: 159229."}]}, "problemtype": {"problemtype_data": [{"description": [{"lang": "en", "value": "CWE-798"}]}]}, "data_version": "4.0", "CVE_data_meta": {"ID": "CVE-2019-4220", "ASSIGNER": "cve@mitre.org"}}, "impact": {"baseMetricV2": {"cvssV2": {"version": "2.0", "baseScore": 2.1, "accessVector": "LOCAL", "vectorString": "AV:L/AC:L/Au:N/C:P/I:N/A:N", "authentication": "NONE", "integrityImpact": "NONE", "accessComplexity": "LOW", "availabilityImpact": "NONE", "confidentialityImpact": "PARTIAL"}, "severity": "LOW", "acInsufInfo": false, "impactScore": 2.9, "obtainAllPrivilege": false, "exploitabilityScore": 3.9, "obtainUserPrivilege": false, "obtainOtherPrivilege": false, "userInteractionRequired": false}, "baseMetricV3": {"cvssV3": {"scope": "UNCHANGED", "version": "3.0", "baseScore": 5.5, "attackVector": "LOCAL", "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "integrityImpact": "NONE", "userInteraction": "NONE", "attackComplexity": "LOW", "availabilityImpact": "NONE", "privilegesRequired": "LOW", "confidentialityImpact": "HIGH"}, "impactScore": 3.6, "exploitabilityScore": 1.8}}, "publishedDate": "2019-06-06T01:29Z", "configurations": {"nodes": [{"operator": "OR", "cpe_match": [{"cpe23Uri": "cpe:2.3:a:ibm:infosphere_information_server_on_cloud:11.7.1.0:*:*:*:*:*:*:*", "vulnerable": true}, {"cpe23Uri": "cpe:2.3:a:ibm:watson_knowledge_catalog:11.7.1.0:*:*:*:*:*:*:*", "vulnerable": true}]}], "CVE_data_version": "4.0"}, "lastModifiedDate": "2019-10-09T23:50Z"}
`, []Vendor{
			{
				Name: "Ibm",
				Products: []Product{
					{
						Name:     "Infosphere Information Server On Cloud",
						URIShort: "ibm:infosphere_information_server_on_cloud",
					},
					{
						Name:     "Watson Knowledge Catalog",
						URIShort: "ibm:watson_knowledge_catalog",
					},
				},
			},
		}},
		{`
{"cve": {"data_type": "CVE", "references": {"reference_data": [{"url": "https://source.android.com/security/bulletin/pixel/2020-06-01", "name": "https://source.android.com/security/bulletin/pixel/2020-06-01", "tags": ["Patch", "Vendor Advisory"], "refsource": "MISC"}]}, "data_format": "MITRE", "description": {"description_data": [{"lang": "en", "value": "In BnDrm::onTransact of IDrm.cpp, there is a possible information disclosure due to uninitialized data. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-146052771"}]}, "problemtype": {"problemtype_data": [{"description": [{"lang": "en", "value": "CWE-200"}]}]}, "data_version": "4.0", "CVE_data_meta": {"ID": "CVE-2020-0134", "ASSIGNER": "cve@mitre.org"}}, "impact": {"baseMetricV2": {"cvssV2": {"version": "2.0", "baseScore": 2.1, "accessVector": "LOCAL", "vectorString": "AV:L/AC:L/Au:N/C:P/I:N/A:N", "authentication": "NONE", "integrityImpact": "NONE", "accessComplexity": "LOW", "availabilityImpact": "NONE", "confidentialityImpact": "PARTIAL"}, "severity": "LOW", "acInsufInfo": false, "impactScore": 2.9, "obtainAllPrivilege": false, "exploitabilityScore": 3.9, "obtainUserPrivilege": false, "obtainOtherPrivilege": false, "userInteractionRequired": false}, "baseMetricV3": {"cvssV3": {"scope": "UNCHANGED", "version": "3.1", "baseScore": 5.5, "attackVector": "LOCAL", "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "integrityImpact": "NONE", "userInteraction": "NONE", "attackComplexity": "LOW", "availabilityImpact": "NONE", "privilegesRequired": "LOW", "confidentialityImpact": "HIGH"}, "impactScore": 3.6, "exploitabilityScore": 1.8}}, "publishedDate": "2020-06-11T15:15Z", "configurations": {"nodes": [{"operator": "OR", "cpe_match": [{"cpe23Uri": "cpe:2.3:o:google:android:10.0:*:*:*:*:*:*:*", "vulnerable": true}]}], "CVE_data_version": "4.0"}, "lastModifiedDate": "2020-06-12T16:37Z"}
`, []Vendor{
			{
				Name: "Google",
				Products: []Product{
					{
						Name:     "Android",
						URIShort: "google:android",
					},
				},
			},
		}},
	}
	for _, tt := range tests {
		var cve CVEItem
		json.Unmarshal([]byte(tt.cveBlob), &cve)
		got := cve.VendorsProducts()
		assert.Equal(t, tt.want, got)
	}

}

func TestClient_FetchCPEMatches(t *testing.T) {
	cl, err := NewClient("tmp")
	if err != nil {
		t.Fatal(err)
	}
	cpeFeed, err := cl.fetchCPEMatches()
	assert.NoError(t, err)

	cpes := cpeFeed.CPEMatches

	// FIXME temporary testing with random 100 picks from cpeFeed
	// for visual checking only at the moment
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(cpes), func(i, j int) { cpes[i], cpes[j] = cpes[j], cpes[i] })
	cpeRand := cpes[:100]

	for i, v := range cpeRand {
		vendors := generateVendorsProducts([]string{v.CPE23URI})
		fmt.Printf("%d: %+v\n", i, vendors)
	}
}
