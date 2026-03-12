package license

import (
	"strings"

	"github.com/ClauGuard/clauguard/pkg/models"
)

// ClassifyLicense classifies a license string into a risk level.
func ClassifyLicense(licenseStr string) (models.LicenseRisk, string) {
	normalized := strings.ToUpper(strings.TrimSpace(licenseStr))

	// Check explicit unknown markers before substring matching
	// "UNLICENSED" (npm) and "NONE" mean no license — must not match "UNLICENSE" (public domain)
	if normalized == "" || normalized == "UNLICENSED" || normalized == "NONE" {
		return models.LicenseRiskUnknown, licenseStr
	}

	// Medium risk — weak copyleft (checked first so LGPL is not caught by GPL)
	for _, l := range mediumRisk {
		if strings.Contains(normalized, l) {
			return models.LicenseRiskMedium, licenseStr
		}
	}

	// High risk — copyleft / viral
	for _, l := range highRisk {
		if strings.Contains(normalized, l) {
			return models.LicenseRiskHigh, licenseStr
		}
	}

	// Low risk — permissive
	for _, l := range lowRisk {
		if strings.Contains(normalized, l) {
			return models.LicenseRiskLow, licenseStr
		}
	}

	return models.LicenseRiskUnknown, licenseStr
}

var highRisk = []string{
	"AGPL",
	"GPL-3",
	"GPLV3",
	"GPL-2",
	"GPLV2",
	"SSPL",
	"EUPL",
	"OSL",
	"CPAL",
	"RPSL",
	"SLEEPYCAT",
	"WATCOM",
	"BUSL",
}

var mediumRisk = []string{
	"LGPL",
	"MPL",
	"EPL",
	"CDDL",
	"CPL",
	"CC-BY-SA",
	"CECILL",
	"ARTISTIC",
}

var lowRisk = []string{
	"MIT",
	"APACHE",
	"BSD",
	"ISC",
	"WTFPL",
	"ZLIB",
	"UNLICENSE",
	"CC0",
	"CC-BY",
	"0BSD",
	"BLUEOAK",
	"PSF",
	"PYTHON",
	"BOOST",
	"BSL-1.0",
}
