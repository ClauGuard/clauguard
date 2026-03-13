package scanner

import (
	"path/filepath"
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func TestGradleParser_Ecosystem(t *testing.T) {
	p := &GradleParser{}
	if p.Ecosystem() != models.EcosystemGradle {
		t.Errorf("expected gradle, got %s", p.Ecosystem())
	}
}

func TestGradleParser_GroovyDeps(t *testing.T) {
	dir := t.TempDir()
	content := `plugins {
    id 'java'
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter:3.2.0'
    api 'com.google.guava:guava:32.1.3-jre'
    testImplementation 'junit:junit:4.13.2'
}
`
	writeTempFile(t, dir, "build.gradle", content)

	p := &GradleParser{}
	deps, err := p.Parse(filepath.Join(dir, "build.gradle"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d", len(deps))
	}

	depMap := map[string]models.Dependency{}
	for _, d := range deps {
		depMap[d.Name] = d
	}

	if depMap["org.springframework.boot:spring-boot-starter"].Version != "3.2.0" {
		t.Errorf("expected 3.2.0, got %s", depMap["org.springframework.boot:spring-boot-starter"].Version)
	}
	if depMap["org.springframework.boot:spring-boot-starter"].IsDev {
		t.Error("implementation should not be dev")
	}
	if !depMap["junit:junit"].IsDev {
		t.Error("testImplementation should be dev")
	}
}

func TestGradleParser_KotlinDSL(t *testing.T) {
	dir := t.TempDir()
	content := `plugins {
    kotlin("jvm") version "1.9.0"
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
}
`
	writeTempFile(t, dir, "build.gradle.kts", content)

	p := &GradleParser{}
	deps, err := p.Parse(filepath.Join(dir, "build.gradle.kts"))
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

	if depMap["org.jetbrains.kotlinx:kotlinx-coroutines-core"].Version != "1.7.3" {
		t.Errorf("expected 1.7.3, got %s", depMap["org.jetbrains.kotlinx:kotlinx-coroutines-core"].Version)
	}
	if !depMap["org.junit.jupiter:junit-jupiter"].IsDev {
		t.Error("testImplementation should be dev")
	}
}

func TestGradleParser_DoubleQuotes(t *testing.T) {
	dir := t.TempDir()
	content := `dependencies {
    implementation "com.squareup.okhttp3:okhttp:4.12.0"
}
`
	writeTempFile(t, dir, "build.gradle", content)

	p := &GradleParser{}
	deps, err := p.Parse(filepath.Join(dir, "build.gradle"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Name != "com.squareup.okhttp3:okhttp" {
		t.Errorf("expected com.squareup.okhttp3:okhttp, got %s", deps[0].Name)
	}
}

func TestGradleParser_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "build.gradle", "// empty build file\n")

	p := &GradleParser{}
	deps, err := p.Parse(filepath.Join(dir, "build.gradle"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestGradleParser_UnknownFile(t *testing.T) {
	p := &GradleParser{}
	deps, err := p.Parse("/some/random.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deps != nil {
		t.Errorf("expected nil, got %v", deps)
	}
}

func TestGradleParser_MissingFile(t *testing.T) {
	p := &GradleParser{}
	_, err := p.Parse("/nonexistent/build.gradle")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestGradleParser_AndroidTestImpl(t *testing.T) {
	dir := t.TempDir()
	content := `dependencies {
    androidTestImplementation 'androidx.test:runner:1.5.2'
}
`
	writeTempFile(t, dir, "build.gradle", content)

	p := &GradleParser{}
	deps, err := p.Parse(filepath.Join(dir, "build.gradle"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if !deps[0].IsDev {
		t.Error("androidTestImplementation should be dev")
	}
}

func TestGradleParser_SourcePathIsSet(t *testing.T) {
	dir := t.TempDir()
	content := `dependencies {
    implementation 'com.example:lib:1.0.0'
}
`
	writeTempFile(t, dir, "build.gradle", content)
	path := filepath.Join(dir, "build.gradle")

	p := &GradleParser{}
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

func TestGradleParser_AllDepsHaveGradleEcosystem(t *testing.T) {
	dir := t.TempDir()
	content := `dependencies {
    implementation 'com.a:lib-a:1.0'
    api 'com.b:lib-b:2.0'
    testImplementation 'com.c:lib-c:3.0'
}
`
	writeTempFile(t, dir, "build.gradle", content)

	p := &GradleParser{}
	deps, err := p.Parse(filepath.Join(dir, "build.gradle"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, d := range deps {
		if d.Ecosystem != models.EcosystemGradle {
			t.Errorf("expected gradle ecosystem, got %s", d.Ecosystem)
		}
	}
}

func TestGradleParser_IgnoresNonDepLines(t *testing.T) {
	dir := t.TempDir()
	content := `plugins {
    id 'java'
}

repositories {
    mavenCentral()
}

// A comment with group:artifact:version pattern
dependencies {
    implementation 'com.example:real-dep:1.0.0'
}

task clean(type: Delete) {
    delete rootProject.buildDir
}
`
	writeTempFile(t, dir, "build.gradle", content)

	p := &GradleParser{}
	deps, err := p.Parse(filepath.Join(dir, "build.gradle"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Name != "com.example:real-dep" {
		t.Errorf("expected com.example:real-dep, got %s", deps[0].Name)
	}
}

func TestGradleParser_MultipleConfigurations(t *testing.T) {
	dir := t.TempDir()
	content := `dependencies {
    implementation 'com.example:impl:1.0'
    compileOnly 'com.example:compile:2.0'
    runtimeOnly 'com.example:runtime:3.0'
    testCompileOnly 'com.example:test-compile:4.0'
    testRuntimeOnly 'com.example:test-runtime:5.0'
}
`
	writeTempFile(t, dir, "build.gradle", content)

	p := &GradleParser{}
	deps, err := p.Parse(filepath.Join(dir, "build.gradle"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 5 {
		t.Fatalf("expected 5 deps, got %d", len(deps))
	}

	depMap := map[string]models.Dependency{}
	for _, d := range deps {
		depMap[d.Name] = d
	}

	if depMap["com.example:impl"].IsDev {
		t.Error("implementation should not be dev")
	}
	if depMap["com.example:compile"].IsDev {
		t.Error("compileOnly should not be dev")
	}
	if depMap["com.example:runtime"].IsDev {
		t.Error("runtimeOnly should not be dev")
	}
	if !depMap["com.example:test-compile"].IsDev {
		t.Error("testCompileOnly should be dev")
	}
	if !depMap["com.example:test-runtime"].IsDev {
		t.Error("testRuntimeOnly should be dev")
	}
}

func TestGradleParser_MissingKtsFile(t *testing.T) {
	p := &GradleParser{}
	_, err := p.Parse("/nonexistent/build.gradle.kts")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestGradleParser_SkipsVariableBasedDeps(t *testing.T) {
	dir := t.TempDir()
	// Variable-based deps like implementation(libs.someLib) won't match the regex
	content := `dependencies {
    implementation(libs.someLib)
    implementation 'com.example:real:1.0.0'
}
`
	writeTempFile(t, dir, "build.gradle", content)

	p := &GradleParser{}
	deps, err := p.Parse(filepath.Join(dir, "build.gradle"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only the string-literal dep should be parsed
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep (skip variable ref), got %d", len(deps))
	}
}
