package license

import (
	"strings"

	"github.com/kemaldelalic/claudeguard/pkg/models"
)

// ClassifyLicense classifies a license string into a risk level.
func ClassifyLicense(licenseStr string) (models.LicenseRisk, string) {
	normalized := strings.ToUpper(strings.TrimSpace(licenseStr))

	// High risk — copyleft / viral
	for _, l := range highRisk {
		if strings.Contains(normalized, l) {
			return models.LicenseRiskHigh, licenseStr
		}
	}

	// Medium risk — weak copyleft
	for _, l := range mediumRisk {
		if strings.Contains(normalized, l) {
			return models.LicenseRiskMedium, licenseStr
		}
	}

	// Low risk — permissive
	for _, l := range lowRisk {
		if strings.Contains(normalized, l) {
			return models.LicenseRiskLow, licenseStr
		}
	}

	if normalized == "" || normalized == "UNLICENSED" || normalized == "NONE" {
		return models.LicenseRiskUnknown, licenseStr
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
	"BLUEOAKMODEL",
	"PSF",
	"PYTHON",
	"BOOST",
	"BSL",
}
