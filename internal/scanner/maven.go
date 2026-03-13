package scanner

import (
	"encoding/xml"
	"os"
	"path/filepath"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func init() {
	Register(&MavenParser{})
}

// MavenParser parses pom.xml files.
type MavenParser struct{}

func (p *MavenParser) Ecosystem() models.Ecosystem {
	return models.EcosystemMaven
}

func (p *MavenParser) Parse(manifestPath string) ([]models.Dependency, error) {
	name := filepath.Base(manifestPath)
	if name != "pom.xml" {
		return nil, nil
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}

	var pom pomXML
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, err
	}

	var deps []models.Dependency

	for _, d := range pom.Dependencies.Entries {
		version := d.Version
		// Resolve property references like ${some.version}
		if len(version) > 3 && version[0] == '$' && version[1] == '{' && version[len(version)-1] == '}' {
			propName := version[2 : len(version)-1]
			if resolved, ok := pom.Properties[propName]; ok {
				version = resolved
			}
		}

		dep := models.Dependency{
			Name:      d.GroupID + ":" + d.ArtifactID,
			Version:   version,
			Ecosystem: models.EcosystemMaven,
			Source:    manifestPath,
			IsDev:     d.Scope == "test" || d.Scope == "provided",
		}
		deps = append(deps, dep)
	}

	// Also parse dependencyManagement entries — these define version constraints
	for _, d := range pom.DependencyManagement.Dependencies.Entries {
		version := d.Version
		if len(version) > 3 && version[0] == '$' && version[1] == '{' && version[len(version)-1] == '}' {
			propName := version[2 : len(version)-1]
			if resolved, ok := pom.Properties[propName]; ok {
				version = resolved
			}
		}

		dep := models.Dependency{
			Name:      d.GroupID + ":" + d.ArtifactID,
			Version:   version,
			Ecosystem: models.EcosystemMaven,
			Source:    manifestPath,
			IsDev:     d.Scope == "test" || d.Scope == "provided",
		}
		deps = append(deps, dep)
	}

	return deps, nil
}

type pomXML struct {
	XMLName              xml.Name             `xml:"project"`
	Properties           pomProperties        `xml:"properties"`
	Dependencies         pomDependencies      `xml:"dependencies"`
	DependencyManagement pomDepMgmt           `xml:"dependencyManagement"`
}

type pomDepMgmt struct {
	Dependencies pomDependencies `xml:"dependencies"`
}

type pomDependencies struct {
	Entries []pomDependency `xml:"dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// pomProperties captures arbitrary <properties> children as a map.
type pomProperties map[string]string

func (p *pomProperties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*p = make(pomProperties)
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var val string
			if err := d.DecodeElement(&val, &t); err != nil {
				return err
			}
			(*p)[t.Name.Local] = val
		case xml.EndElement:
			return nil
		}
	}
}
