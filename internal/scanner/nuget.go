package scanner

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func init() {
	Register(&NugetParser{})
}

// NugetParser parses .csproj and packages.config files.
type NugetParser struct{}

func (p *NugetParser) Ecosystem() models.Ecosystem {
	return models.EcosystemNuget
}

func (p *NugetParser) Parse(manifestPath string) ([]models.Dependency, error) {
	name := filepath.Base(manifestPath)

	switch {
	case name == "packages.config":
		return p.parsePackagesConfig(manifestPath)
	case strings.HasSuffix(name, ".csproj"):
		return p.parseCsproj(manifestPath)
	default:
		return nil, nil
	}
}

func (p *NugetParser) parseCsproj(path string) ([]models.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var project csprojXML
	if err := xml.Unmarshal(data, &project); err != nil {
		return nil, err
	}

	var deps []models.Dependency
	for _, group := range project.ItemGroups {
		for _, ref := range group.PackageReferences {
			if ref.Include == "" {
				continue
			}
			version := ref.Version
			if version == "" {
				version = ref.VersionElement
			}
			deps = append(deps, models.Dependency{
				Name:      ref.Include,
				Version:   version,
				Ecosystem: models.EcosystemNuget,
				Source:    path,
			})
		}
	}

	return deps, nil
}

func (p *NugetParser) parsePackagesConfig(path string) ([]models.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config packagesConfigXML
	if err := xml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	var deps []models.Dependency
	for _, pkg := range config.Packages {
		if pkg.ID == "" {
			continue
		}
		deps = append(deps, models.Dependency{
			Name:      pkg.ID,
			Version:   pkg.Version,
			Ecosystem: models.EcosystemNuget,
			Source:    path,
			IsDev:     pkg.DevelopmentDependency == "true",
		})
	}

	return deps, nil
}

type csprojXML struct {
	XMLName    xml.Name         `xml:"Project"`
	ItemGroups []csprojItemGroup `xml:"ItemGroup"`
}

type csprojItemGroup struct {
	PackageReferences []csprojPackageRef `xml:"PackageReference"`
}

type csprojPackageRef struct {
	Include        string `xml:"Include,attr"`
	Version        string `xml:"Version,attr"`
	VersionElement string `xml:"Version"`
}

type packagesConfigXML struct {
	XMLName  xml.Name             `xml:"packages"`
	Packages []packagesConfigPkg  `xml:"package"`
}

type packagesConfigPkg struct {
	ID                    string `xml:"id,attr"`
	Version               string `xml:"version,attr"`
	DevelopmentDependency string `xml:"developmentDependency,attr"`
}
