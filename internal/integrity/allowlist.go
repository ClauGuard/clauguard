package integrity

// allowlist contains known-legitimate packages that would otherwise trigger
// false positive integrity alerts. These are real packages, not typosquats.
var allowlist = map[string]bool{
	// npm packages that are close to other popular names
	"color":         true, // legit package, not a typosquat of "colors"
	"colours":       true, // British English variant
	"source-map-js": true, // maintained fork of source-map
	"node-fetch":    true, // legit fetch polyfill
	"node-forge":    true, // legit crypto library
	"get-port":      true, // legit utility
	"get-stream":    true, // legit utility
	"get-stdin":     true, // legit utility
	"get-value":     true, // legit utility
	"require-main-filename": true,
	"require-directory":     true,

	// Scoped packages where the base name matches popular names
	"rect":    true, // @radix-ui/rect, not a typosquat of "react"
	"core":    true, // used in many scoped packages (@floating-ui/core, @babel/core)
	"utils":   true, // common scoped base name
	"helpers": true, // common scoped base name
	"cli":     true, // common scoped base name
	"types":   true, // common scoped base name
	"runtime": true, // common scoped base name
	"server":  true, // common scoped base name
	"client":  true, // common scoped base name
	"config":  true, // common scoped base name
	"plugin":  true, // common scoped base name

	// PyPI packages
	"python-dateutil": true, // legit, not combosquat of dateutil
	"py-cpuinfo":      true, // legit system info package

	// Go modules that look similar to others
	"github.com/pkg/errors":  true, // legit, pre-dates stdlib errors
	"github.com/pkg/sftp":    true, // legit SFTP library
	"github.com/lib/pq":      true, // legit postgres driver
	"github.com/go-sql-driver/mysql": true, // legit mysql driver
}

// isAllowlisted checks if a package name (or its base name for scoped packages)
// is in the known-legitimate allowlist.
func isAllowlisted(name, baseName string) bool {
	return allowlist[name] || allowlist[baseName]
}
