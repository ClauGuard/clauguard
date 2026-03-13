package scanner

import (
	"path/filepath"
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func TestMavenParser_Ecosystem(t *testing.T) {
	p := &MavenParser{}
	if p.Ecosystem() != models.EcosystemMaven {
		t.Errorf("expected maven, got %s", p.Ecosystem())
	}
}

func TestMavenParser_BasicPom(t *testing.T) {
	dir := t.TempDir()
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>6.1.0</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>`
	writeTempFile(t, dir, "pom.xml", content)

	p := &MavenParser{}
	deps, err := p.Parse(filepath.Join(dir, "pom.xml"))
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

	spring := depMap["org.springframework:spring-core"]
	if spring.Version != "6.1.0" {
		t.Errorf("expected 6.1.0, got %s", spring.Version)
	}
	if spring.IsDev {
		t.Error("spring-core should not be dev")
	}

	junit := depMap["junit:junit"]
	if !junit.IsDev {
		t.Error("junit should be dev (test scope)")
	}
}

func TestMavenParser_PropertyResolution(t *testing.T) {
	dir := t.TempDir()
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <properties>
    <spring.version>6.1.0</spring.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
  </dependencies>
</project>`
	writeTempFile(t, dir, "pom.xml", content)

	p := &MavenParser{}
	deps, err := p.Parse(filepath.Join(dir, "pom.xml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Version != "6.1.0" {
		t.Errorf("expected resolved version 6.1.0, got %s", deps[0].Version)
	}
}

func TestMavenParser_DependencyManagement(t *testing.T) {
	dir := t.TempDir()
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.google.guava</groupId>
        <artifactId>guava</artifactId>
        <version>32.1.3-jre</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`
	writeTempFile(t, dir, "pom.xml", content)

	p := &MavenParser{}
	deps, err := p.Parse(filepath.Join(dir, "pom.xml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Name != "com.google.guava:guava" {
		t.Errorf("expected com.google.guava:guava, got %s", deps[0].Name)
	}
}

func TestMavenParser_ProvidedScope(t *testing.T) {
	dir := t.TempDir()
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>javax.servlet</groupId>
      <artifactId>servlet-api</artifactId>
      <version>2.5</version>
      <scope>provided</scope>
    </dependency>
  </dependencies>
</project>`
	writeTempFile(t, dir, "pom.xml", content)

	p := &MavenParser{}
	deps, err := p.Parse(filepath.Join(dir, "pom.xml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !deps[0].IsDev {
		t.Error("provided scope should be marked as dev")
	}
}

func TestMavenParser_EmptyPom(t *testing.T) {
	dir := t.TempDir()
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
</project>`
	writeTempFile(t, dir, "pom.xml", content)

	p := &MavenParser{}
	deps, err := p.Parse(filepath.Join(dir, "pom.xml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestMavenParser_UnknownFile(t *testing.T) {
	p := &MavenParser{}
	deps, err := p.Parse("/some/random.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deps != nil {
		t.Errorf("expected nil, got %v", deps)
	}
}

func TestMavenParser_MissingFile(t *testing.T) {
	p := &MavenParser{}
	_, err := p.Parse("/nonexistent/pom.xml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestMavenParser_InvalidXML(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "pom.xml", "NOT XML AT ALL")

	p := &MavenParser{}
	_, err := p.Parse(filepath.Join(dir, "pom.xml"))
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}

func TestMavenParser_SourcePathIsSet(t *testing.T) {
	dir := t.TempDir()
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>lib</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>`
	writeTempFile(t, dir, "pom.xml", content)
	path := filepath.Join(dir, "pom.xml")

	p := &MavenParser{}
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

func TestMavenParser_AllDepsHaveMavenEcosystem(t *testing.T) {
	dir := t.TempDir()
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.a</groupId>
      <artifactId>lib-a</artifactId>
      <version>1.0</version>
    </dependency>
    <dependency>
      <groupId>com.b</groupId>
      <artifactId>lib-b</artifactId>
      <version>2.0</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>`
	writeTempFile(t, dir, "pom.xml", content)

	p := &MavenParser{}
	deps, err := p.Parse(filepath.Join(dir, "pom.xml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, d := range deps {
		if d.Ecosystem != models.EcosystemMaven {
			t.Errorf("expected maven ecosystem, got %s", d.Ecosystem)
		}
	}
}

func TestMavenParser_UnresolvedProperty(t *testing.T) {
	dir := t.TempDir()
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>lib</artifactId>
      <version>${undefined.version}</version>
    </dependency>
  </dependencies>
</project>`
	writeTempFile(t, dir, "pom.xml", content)

	p := &MavenParser{}
	deps, err := p.Parse(filepath.Join(dir, "pom.xml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Unresolved property should be kept as-is
	if deps[0].Version != "${undefined.version}" {
		t.Errorf("expected raw property reference, got %s", deps[0].Version)
	}
}

func TestMavenParser_NoVersionDep(t *testing.T) {
	dir := t.TempDir()
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>lib</artifactId>
    </dependency>
  </dependencies>
</project>`
	writeTempFile(t, dir, "pom.xml", content)

	p := &MavenParser{}
	deps, err := p.Parse(filepath.Join(dir, "pom.xml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Version != "" {
		t.Errorf("expected empty version, got %s", deps[0].Version)
	}
}

func TestMavenParser_RuntimeScopeNotDev(t *testing.T) {
	dir := t.TempDir()
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>lib</artifactId>
      <version>1.0</version>
      <scope>runtime</scope>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>compile-lib</artifactId>
      <version>2.0</version>
      <scope>compile</scope>
    </dependency>
  </dependencies>
</project>`
	writeTempFile(t, dir, "pom.xml", content)

	p := &MavenParser{}
	deps, err := p.Parse(filepath.Join(dir, "pom.xml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, d := range deps {
		if d.IsDev {
			t.Errorf("%s with scope should not be dev", d.Name)
		}
	}
}

func TestMavenParser_BothDepsAndDepMgmt(t *testing.T) {
	dir := t.TempDir()
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <properties>
    <guava.version>32.0</guava.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.google.guava</groupId>
        <artifactId>guava</artifactId>
        <version>${guava.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.0</version>
    </dependency>
  </dependencies>
</project>`
	writeTempFile(t, dir, "pom.xml", content)

	p := &MavenParser{}
	deps, err := p.Parse(filepath.Join(dir, "pom.xml"))
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

	if depMap["com.google.guava:guava"].Version != "32.0" {
		t.Errorf("expected resolved 32.0, got %s", depMap["com.google.guava:guava"].Version)
	}
	if depMap["org.slf4j:slf4j-api"].Version != "2.0.0" {
		t.Errorf("expected 2.0.0, got %s", depMap["org.slf4j:slf4j-api"].Version)
	}
}
