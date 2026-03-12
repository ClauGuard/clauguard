package license

import (
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func TestClassifyLicense(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantRisk    models.LicenseRisk
		wantLicense string
	}{
		// --- High risk (copyleft / viral) ---
		{"high: AGPL-3.0", "AGPL-3.0", models.LicenseRiskHigh, "AGPL-3.0"},
		{"high: GPL-3.0-only", "GPL-3.0-only", models.LicenseRiskHigh, "GPL-3.0-only"},
		{"high: GPL-2.0", "GPL-2.0", models.LicenseRiskHigh, "GPL-2.0"},
		{"high: GPLv3", "GPLv3", models.LicenseRiskHigh, "GPLv3"},
		{"high: GPLv2", "GPLv2", models.LicenseRiskHigh, "GPLv2"},
		{"high: SSPL-1.0", "SSPL-1.0", models.LicenseRiskHigh, "SSPL-1.0"},
		{"high: EUPL-1.2", "EUPL-1.2", models.LicenseRiskHigh, "EUPL-1.2"},
		{"high: OSL-3.0", "OSL-3.0", models.LicenseRiskHigh, "OSL-3.0"},
		{"high: CPAL-1.0", "CPAL-1.0", models.LicenseRiskHigh, "CPAL-1.0"},
		{"high: RPSL-1.0", "RPSL-1.0", models.LicenseRiskHigh, "RPSL-1.0"},
		{"high: Sleepycat", "Sleepycat", models.LicenseRiskHigh, "Sleepycat"},
		{"high: Watcom-1.0", "Watcom-1.0", models.LicenseRiskHigh, "Watcom-1.0"},
		{"high: BUSL-1.1", "BUSL-1.1", models.LicenseRiskHigh, "BUSL-1.1"},

		// --- Medium risk (weak copyleft) ---
		{"medium: LGPL-2.1", "LGPL-2.1", models.LicenseRiskMedium, "LGPL-2.1"},
		{"medium: LGPL-3.0", "LGPL-3.0", models.LicenseRiskMedium, "LGPL-3.0"},
		{"medium: MPL-2.0", "MPL-2.0", models.LicenseRiskMedium, "MPL-2.0"},
		{"medium: EPL-2.0", "EPL-2.0", models.LicenseRiskMedium, "EPL-2.0"},
		{"medium: CDDL-1.0", "CDDL-1.0", models.LicenseRiskMedium, "CDDL-1.0"},
		{"medium: CPL-1.0", "CPL-1.0", models.LicenseRiskMedium, "CPL-1.0"},
		{"medium: CC-BY-SA-4.0", "CC-BY-SA-4.0", models.LicenseRiskMedium, "CC-BY-SA-4.0"},
		{"medium: CeCILL-2.1", "CeCILL-2.1", models.LicenseRiskMedium, "CeCILL-2.1"},
		{"medium: Artistic-2.0", "Artistic-2.0", models.LicenseRiskMedium, "Artistic-2.0"},

		// --- CRITICAL: LGPL must be medium, not high from GPL substring ---
		{"LGPL-2.1 must be medium not high", "LGPL-2.1", models.LicenseRiskMedium, "LGPL-2.1"},
		{"LGPL-3.0 must be medium not high", "LGPL-3.0", models.LicenseRiskMedium, "LGPL-3.0"},

		// --- Low risk (permissive) ---
		{"low: MIT", "MIT", models.LicenseRiskLow, "MIT"},
		{"low: Apache-2.0", "Apache-2.0", models.LicenseRiskLow, "Apache-2.0"},
		{"low: BSD-3-Clause", "BSD-3-Clause", models.LicenseRiskLow, "BSD-3-Clause"},
		{"low: BSD-2-Clause", "BSD-2-Clause", models.LicenseRiskLow, "BSD-2-Clause"},
		{"low: ISC", "ISC", models.LicenseRiskLow, "ISC"},
		{"low: WTFPL", "WTFPL", models.LicenseRiskLow, "WTFPL"},
		{"low: Zlib", "Zlib", models.LicenseRiskLow, "Zlib"},
		{"low: Unlicense", "Unlicense", models.LicenseRiskLow, "Unlicense"},
		{"low: CC0-1.0", "CC0-1.0", models.LicenseRiskLow, "CC0-1.0"},
		{"low: CC-BY-4.0", "CC-BY-4.0", models.LicenseRiskLow, "CC-BY-4.0"},
		{"low: 0BSD", "0BSD", models.LicenseRiskLow, "0BSD"},
		{"low: BlueOakModel (no hyphens)", "BlueOakModel", models.LicenseRiskLow, "BlueOakModel"},
		{"low: BlueOak-Model-License", "BlueOak-Model-License", models.LicenseRiskLow, "BlueOak-Model-License"},
		{"low: PSF-2.0", "PSF-2.0", models.LicenseRiskLow, "PSF-2.0"},
		{"low: Python-2.0", "Python-2.0", models.LicenseRiskLow, "Python-2.0"},
		{"low: BSL-1.0", "BSL-1.0", models.LicenseRiskLow, "BSL-1.0"},
		{"low: Boost Software License", "Boost Software License", models.LicenseRiskLow, "Boost Software License"},

		// --- CRITICAL: BSL vs BUSL ---
		{"BSL-1.0 must be low (Boost)", "BSL-1.0", models.LicenseRiskLow, "BSL-1.0"},
		{"BUSL-1.1 must be high (Business Source)", "BUSL-1.1", models.LicenseRiskHigh, "BUSL-1.1"},

		// --- Unknown ---
		{"unknown: empty string", "", models.LicenseRiskUnknown, ""},
		{"unknown: UNLICENSED", "UNLICENSED", models.LicenseRiskUnknown, "UNLICENSED"},
		{"unknown: NONE", "NONE", models.LicenseRiskUnknown, "NONE"},
		{"unknown: Proprietary", "Proprietary", models.LicenseRiskUnknown, "Proprietary"},
		{"unknown: Custom License", "Custom License", models.LicenseRiskUnknown, "Custom License"},

		// --- Case insensitivity ---
		{"case: lowercase mit", "mit", models.LicenseRiskLow, "mit"},
		{"case: uppercase MIT", "MIT", models.LicenseRiskLow, "MIT"},
		{"case: mixed case Mit", "Mit", models.LicenseRiskLow, "Mit"},
		{"case: lowercase gpl-3.0", "gpl-3.0", models.LicenseRiskHigh, "gpl-3.0"},
		{"case: mixed case Lgpl-2.1", "Lgpl-2.1", models.LicenseRiskMedium, "Lgpl-2.1"},

		// --- Whitespace handling ---
		{"whitespace: leading/trailing MIT", "  MIT  ", models.LicenseRiskLow, "  MIT  "},
		{"whitespace: leading/trailing GPL-3.0", "  GPL-3.0  ", models.LicenseRiskHigh, "  GPL-3.0  "},
		{"whitespace: leading/trailing LGPL-2.1", " LGPL-2.1 ", models.LicenseRiskMedium, " LGPL-2.1 "},
		{"whitespace: only spaces", "   ", models.LicenseRiskUnknown, "   "},

		// --- Compound / multi-license strings ---
		{"compound: BSD + GPL should be high (GPL substring match)", "BSD-3-Clause, GPL-2.0-only", models.LicenseRiskHigh, "BSD-3-Clause, GPL-2.0-only"},
		{"compound: MIT OR Apache should be low", "MIT OR Apache-2.0", models.LicenseRiskLow, "MIT OR Apache-2.0"},
		{"compound: LGPL + GPL should be medium (LGPL checked first)", "LGPL-2.1 OR GPL-3.0", models.LicenseRiskMedium, "LGPL-2.1 OR GPL-3.0"},

		// --- CC-BY-SA must be medium, not low from CC-BY match ---
		{"CC-BY-SA checked before CC-BY", "CC-BY-SA-4.0", models.LicenseRiskMedium, "CC-BY-SA-4.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRisk, gotLicense := ClassifyLicense(tt.input)

			if gotRisk != tt.wantRisk {
				t.Errorf("ClassifyLicense(%q) risk = %q, want %q", tt.input, gotRisk, tt.wantRisk)
			}
			if gotLicense != tt.wantLicense {
				t.Errorf("ClassifyLicense(%q) license = %q, want %q", tt.input, gotLicense, tt.wantLicense)
			}
		})
	}
}
