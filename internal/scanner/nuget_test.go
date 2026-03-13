package scanner

import (
	"path/filepath"
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func TestNugetParser_Ecosystem(t *testing.T) {
	p := &NugetParser{}
	if p.Ecosystem() != models.EcosystemNuget {
		t.Errorf("expected nuget, got %s", p.Ecosystem())
	}
}

func TestNugetParser_Csproj_PackageReferences(t *testing.T) {
	dir := t.TempDir()
	content := `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>`
	writeTempFile(t, dir, "MyApp.csproj", content)

	p := &NugetParser{}
	deps, err := p.Parse(filepath.Join(dir, "MyApp.csproj"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}

	depMap := map[string]models.Dependency{}
	for _, d := range deps {
		depMap[d.Name] = d
	}

	if depMap["Newtonsoft.Json"].Version != "13.0.3" {
		t.Errorf("expected 13.0.3, got %s", depMap["Newtonsoft.Json"].Version)
	}
	if depMap["Serilog"].Version != "3.1.1" {
		t.Errorf("expected 3.1.1, got %s", depMap["Serilog"].Version)
	}
}

func TestNugetParser_Csproj_VersionAsElement(t *testing.T) {
	dir := t.TempDir()
	content := `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="AutoMapper">
      <Version>12.0.1</Version>
    </PackageReference>
  </ItemGroup>
</Project>`
	writeTempFile(t, dir, "MyApp.csproj", content)

	p := &NugetParser{}
	deps, err := p.Parse(filepath.Join(dir, "MyApp.csproj"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Version != "12.0.1" {
		t.Errorf("expected 12.0.1, got %s", deps[0].Version)
	}
}

func TestNugetParser_PackagesConfig(t *testing.T) {
	dir := t.TempDir()
	content := `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
  <package id="xunit" version="2.6.2" targetFramework="net48" developmentDependency="true" />
</packages>`
	writeTempFile(t, dir, "packages.config", content)

	p := &NugetParser{}
	deps, err := p.Parse(filepath.Join(dir, "packages.config"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}

	depMap := map[string]models.Dependency{}
	for _, d := range deps {
		depMap[d.Name] = d
	}

	if depMap["Newtonsoft.Json"].Version != "13.0.3" {
		t.Errorf("expected 13.0.3, got %s", depMap["Newtonsoft.Json"].Version)
	}
	if depMap["Newtonsoft.Json"].IsDev {
		t.Error("Newtonsoft.Json should not be dev")
	}
	if !depMap["xunit"].IsDev {
		t.Error("xunit should be dev (developmentDependency=true)")
	}
}

func TestNugetParser_EmptyCsproj(t *testing.T) {
	dir := t.TempDir()
	content := `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
</Project>`
	writeTempFile(t, dir, "MyApp.csproj", content)

	p := &NugetParser{}
	deps, err := p.Parse(filepath.Join(dir, "MyApp.csproj"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestNugetParser_MultipleItemGroups(t *testing.T) {
	dir := t.TempDir()
	content := `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="MediatR" Version="12.2.0" />
  </ItemGroup>
  <ItemGroup>
    <PackageReference Include="FluentValidation" Version="11.9.0" />
  </ItemGroup>
</Project>`
	writeTempFile(t, dir, "MyApp.csproj", content)

	p := &NugetParser{}
	deps, err := p.Parse(filepath.Join(dir, "MyApp.csproj"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
}

func TestNugetParser_UnknownFile(t *testing.T) {
	p := &NugetParser{}
	deps, err := p.Parse("/some/random.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deps != nil {
		t.Errorf("expected nil, got %v", deps)
	}
}

func TestNugetParser_MissingFile(t *testing.T) {
	p := &NugetParser{}
	_, err := p.Parse("/nonexistent/packages.config")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestNugetParser_MissingCsprojFile(t *testing.T) {
	p := &NugetParser{}
	_, err := p.Parse("/nonexistent/MyApp.csproj")
	if err == nil {
		t.Error("expected error for missing csproj file")
	}
}

func TestNugetParser_InvalidCsprojXML(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "MyApp.csproj", "NOT XML AT ALL")

	p := &NugetParser{}
	_, err := p.Parse(filepath.Join(dir, "MyApp.csproj"))
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}

func TestNugetParser_InvalidPackagesConfigXML(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "packages.config", "BROKEN XML")

	p := &NugetParser{}
	_, err := p.Parse(filepath.Join(dir, "packages.config"))
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}

func TestNugetParser_SourcePathIsSet(t *testing.T) {
	dir := t.TempDir()
	content := `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="SomePkg" Version="1.0.0" />
  </ItemGroup>
</Project>`
	writeTempFile(t, dir, "MyApp.csproj", content)
	path := filepath.Join(dir, "MyApp.csproj")

	p := &NugetParser{}
	deps, err := p.Parse(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Source != path {
		t.Errorf("expected source %s, got %s", path, deps[0].Source)
	}
}

func TestNugetParser_AllDepsHaveNugetEcosystem(t *testing.T) {
	dir := t.TempDir()
	content := `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="PkgA" Version="1.0" />
    <PackageReference Include="PkgB" Version="2.0" />
  </ItemGroup>
</Project>`
	writeTempFile(t, dir, "MyApp.csproj", content)

	p := &NugetParser{}
	deps, err := p.Parse(filepath.Join(dir, "MyApp.csproj"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, d := range deps {
		if d.Ecosystem != models.EcosystemNuget {
			t.Errorf("expected nuget ecosystem, got %s", d.Ecosystem)
		}
	}
}

func TestNugetParser_EmptyPackagesConfig(t *testing.T) {
	dir := t.TempDir()
	content := `<?xml version="1.0" encoding="utf-8"?>
<packages>
</packages>`
	writeTempFile(t, dir, "packages.config", content)

	p := &NugetParser{}
	deps, err := p.Parse(filepath.Join(dir, "packages.config"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestNugetParser_Csproj_SkipsEmptyInclude(t *testing.T) {
	dir := t.TempDir()
	content := `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="" Version="1.0.0" />
    <PackageReference Include="ValidPkg" Version="2.0.0" />
  </ItemGroup>
</Project>`
	writeTempFile(t, dir, "MyApp.csproj", content)

	p := &NugetParser{}
	deps, err := p.Parse(filepath.Join(dir, "MyApp.csproj"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep (skip empty Include), got %d", len(deps))
	}
	if deps[0].Name != "ValidPkg" {
		t.Errorf("expected ValidPkg, got %s", deps[0].Name)
	}
}

func TestNugetParser_PackagesConfig_SkipsEmptyID(t *testing.T) {
	dir := t.TempDir()
	content := `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="" version="1.0.0" />
  <package id="ValidPkg" version="2.0.0" />
</packages>`
	writeTempFile(t, dir, "packages.config", content)

	p := &NugetParser{}
	deps, err := p.Parse(filepath.Join(dir, "packages.config"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep (skip empty id), got %d", len(deps))
	}
}

func TestNugetParser_Csproj_VersionAttrTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	// When both attribute and element Version exist, attribute should win
	content := `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="SomePkg" Version="1.0.0">
      <Version>2.0.0</Version>
    </PackageReference>
  </ItemGroup>
</Project>`
	writeTempFile(t, dir, "MyApp.csproj", content)

	p := &NugetParser{}
	deps, err := p.Parse(filepath.Join(dir, "MyApp.csproj"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	// Attribute should take precedence
	if deps[0].Version != "1.0.0" {
		t.Errorf("expected 1.0.0 (attr), got %s", deps[0].Version)
	}
}
