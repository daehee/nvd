package nvd

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// https://cve.mitre.org/cve/identifiers/tech-guidance.html#extraction_or_parsing
var CVERx = regexp.MustCompile(`^CVE-([0-9]{4})-[0-9]{4,}$`)             // Implied Strict
var CVERxLoose = regexp.MustCompile(`CVE[^\w]*\d{4}[^\w]+\d{4,}`)        // Loose
var CVERxStrict = regexp.MustCompile(`^CVE-\d{4}-(0\d{3}|[1-9]\d{3,})$`) // Strict

// IsCVEIDLoose matches on "Loose" specification from MITRE, and ensures that
// 1. there is a CVE prefix,
// 2. followed by zero or more non-alphanumeric characters (whether spaces, hyphens, etc.),
// 3. with a 4-digit year, followed by at least one non-alphanumeric character, and at least 4 digits.
// This would accept IDs such as "CVE: 2014-1234", "CVE_2014_1234", etc.
// Usage: scraping CVEs
func IsCVEIDLoose(cveID string) bool {
	return CVERxLoose.MatchString(cveID)
}

// IsCVEID matched on "Implied Strict" specification from MITRE, which is
// the simplest regular expression that does not mark any valid IDs as invalid;
// however, it removes the check for the leading 0 when there are 5 or more digits
// in the sequence number.
func IsCVEID(cveID string) bool {
	return CVERx.MatchString(cveID)
}

// IsCVEIDStrict matches on "Strict" specification from MITRE, and ensures that
// 1. the year is 4 digits
// 2. a sequence number cannot have a leading zero if it is 5 digits or more
// 3. that every sequence number must have at least 4 digits.
// 4. year is 2002 or greater, and not in a future year
// Usage: data operations against NVD database or pre-validated data entries
func IsCVEIDStrict(cveID string) bool {
	if !CVERxStrict.MatchString(cveID) {
		return false
	}

	year, _ := ParseCVEID(cveID)
	if year < 2002 || year > time.Now().Year() {
		return false
	}

	return true
}

func ParseCVEID(cveID string) (cveYear int, cveSequence int) {
	split := strings.Split(cveID, "-")
	cveYear, _ = strconv.Atoi(split[1])
	cveSequence, _ = strconv.Atoi(split[2])
	return
}

func PadCVESequence(seq int) string {
	padStr := "0"
	overallLen := 4
	seqStr := strconv.Itoa(seq)
	if len(seqStr) >= overallLen {
		return seqStr
	}
	var padCountInt = 1 + ((overallLen - len(padStr)) / len(padStr))
	var retStr = strings.Repeat(padStr, padCountInt) + seqStr
	return retStr[(len(retStr) - overallLen):]
}

// FixCVEID attempts to fix invalid CVE ID by sanitizing sequence
func FixCVEID(cveID string) string {
	year, sequence := ParseCVEID(cveID)
	fixedSeq := PadCVESequence(sequence)
	return fmt.Sprintf("CVE-%d-%s", year, fixedSeq)
}

// IDNotFound is a custom error type to notify consumer that CVE ID was not found
// type IDNotFound struct {
// 	CVEID string
// 	Year  string
// 	Msg   string
// }
//
// func (e IDNotFound) Error() string {
// 	return fmt.Sprintf("%q not found in NVD (%s feed) or MITRE: %s", e.CVEID, e.Year, e.Msg)
// }
