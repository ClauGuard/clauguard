package scanner

import (
	"path/filepath"
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func TestCocoaPodsParser_Ecosystem(t *testing.T) {
	p := &CocoaPodsParser{}
	if p.Ecosystem() != models.EcosystemCocoaPod {
		t.Errorf("expected cocoapods, got %s", p.Ecosystem())
	}
}

func TestCocoaPodsParser_Podfile(t *testing.T) {
	dir := t.TempDir()
	content := `platform :ios, '15.0'

target 'MyApp' do
  use_frameworks!

  pod 'Alamofire', '~> 5.8'
  pod 'SwiftyJSON', '5.0.1'
  pod 'SnapKit'
end
`
	writeTempFile(t, dir, "Podfile", content)

	p := &CocoaPodsParser{}
	deps, err := p.Parse(filepath.Join(dir, "Podfile"))
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

	if depMap["Alamofire"].Version != "~> 5.8" {
		t.Errorf("expected ~> 5.8, got %s", depMap["Alamofire"].Version)
	}
	if depMap["SwiftyJSON"].Version != "5.0.1" {
		t.Errorf("expected 5.0.1, got %s", depMap["SwiftyJSON"].Version)
	}
	if depMap["SnapKit"].Version != "*" {
		t.Errorf("expected *, got %s", depMap["SnapKit"].Version)
	}
}

func TestCocoaPodsParser_PodfileLock(t *testing.T) {
	dir := t.TempDir()
	content := `PODS:
  - Alamofire (5.8.1)
  - SwiftyJSON (5.0.1):
    - SomeSubDep
  - SnapKit (5.6.0)

DEPENDENCIES:
  - Alamofire (~> 5.8)
  - SwiftyJSON (= 5.0.1)
  - SnapKit

SPEC REPOS:
  trunk:
    - Alamofire
`
	writeTempFile(t, dir, "Podfile.lock", content)

	p := &CocoaPodsParser{}
	deps, err := p.Parse(filepath.Join(dir, "Podfile.lock"))
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

	if depMap["Alamofire"].Version != "5.8.1" {
		t.Errorf("expected 5.8.1, got %s", depMap["Alamofire"].Version)
	}
	if depMap["SwiftyJSON"].Version != "5.0.1" {
		t.Errorf("expected 5.0.1, got %s", depMap["SwiftyJSON"].Version)
	}
	if depMap["SnapKit"].Version != "5.6.0" {
		t.Errorf("expected 5.6.0, got %s", depMap["SnapKit"].Version)
	}
}

func TestCocoaPodsParser_PodfileLock_SkipsSubDeps(t *testing.T) {
	dir := t.TempDir()
	content := `PODS:
  - Firebase (10.18.0):
    - FirebaseAnalytics (~> 10.18.0)
    - FirebaseAuth (~> 10.18.0)
  - FirebaseAnalytics (10.18.0)

DEPENDENCIES:
  - Firebase
`
	writeTempFile(t, dir, "Podfile.lock", content)

	p := &CocoaPodsParser{}
	deps, err := p.Parse(filepath.Join(dir, "Podfile.lock"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should only get top-level pods (2 spaces), not sub-deps (4 spaces)
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps (Firebase + FirebaseAnalytics), got %d", len(deps))
	}
}

func TestCocoaPodsParser_EmptyPodfile(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "Podfile", "# empty\n")

	p := &CocoaPodsParser{}
	deps, err := p.Parse(filepath.Join(dir, "Podfile"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestCocoaPodsParser_UnknownFile(t *testing.T) {
	p := &CocoaPodsParser{}
	deps, err := p.Parse("/some/random.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deps != nil {
		t.Errorf("expected nil, got %v", deps)
	}
}

func TestCocoaPodsParser_MissingFile(t *testing.T) {
	p := &CocoaPodsParser{}
	_, err := p.Parse("/nonexistent/Podfile")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParsePodEntry_WithVersion(t *testing.T) {
	name, version := parsePodEntry("Alamofire (5.8.1)")
	if name != "Alamofire" {
		t.Errorf("expected Alamofire, got %s", name)
	}
	if version != "5.8.1" {
		t.Errorf("expected 5.8.1, got %s", version)
	}
}

func TestParsePodEntry_WithColon(t *testing.T) {
	name, version := parsePodEntry("SwiftyJSON (5.0.1):")
	if name != "SwiftyJSON" {
		t.Errorf("expected SwiftyJSON, got %s", name)
	}
	if version != "5.0.1" {
		t.Errorf("expected 5.0.1, got %s", version)
	}
}

func TestParsePodEntry_NoVersion(t *testing.T) {
	name, version := parsePodEntry("SomePod")
	if name != "SomePod" {
		t.Errorf("expected SomePod, got %s", name)
	}
	if version != "" {
		t.Errorf("expected empty, got %s", version)
	}
}

func TestCocoaPodsParser_SourcePathIsSet(t *testing.T) {
	dir := t.TempDir()
	content := `pod 'Alamofire', '5.0'
`
	writeTempFile(t, dir, "Podfile", content)
	path := filepath.Join(dir, "Podfile")

	p := &CocoaPodsParser{}
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

func TestCocoaPodsParser_AllDepsHaveCocoaPodsEcosystem(t *testing.T) {
	dir := t.TempDir()
	content := `pod 'Alamofire', '5.0'
pod 'SwiftyJSON'
`
	writeTempFile(t, dir, "Podfile", content)

	p := &CocoaPodsParser{}
	deps, err := p.Parse(filepath.Join(dir, "Podfile"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, d := range deps {
		if d.Ecosystem != models.EcosystemCocoaPod {
			t.Errorf("expected cocoapods ecosystem, got %s", d.Ecosystem)
		}
	}
}

func TestCocoaPodsParser_MissingLockFile(t *testing.T) {
	p := &CocoaPodsParser{}
	_, err := p.Parse("/nonexistent/Podfile.lock")
	if err == nil {
		t.Error("expected error for missing lock file")
	}
}

func TestCocoaPodsParser_PodfileLock_EmptyPodsSection(t *testing.T) {
	dir := t.TempDir()
	content := `PODS:

DEPENDENCIES:

SPEC REPOS:
  trunk: []
`
	writeTempFile(t, dir, "Podfile.lock", content)

	p := &CocoaPodsParser{}
	deps, err := p.Parse(filepath.Join(dir, "Podfile.lock"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestCocoaPodsParser_Podfile_NonPodLinesSkipped(t *testing.T) {
	dir := t.TempDir()
	content := `platform :ios, '15.0'
use_frameworks!

# This is a comment
source 'https://cdn.cocoapods.org/'

target 'MyApp' do
  pod 'Alamofire', '5.0'
end

post_install do |installer|
  puts "done"
end
`
	writeTempFile(t, dir, "Podfile", content)

	p := &CocoaPodsParser{}
	deps, err := p.Parse(filepath.Join(dir, "Podfile"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Name != "Alamofire" {
		t.Errorf("expected Alamofire, got %s", deps[0].Name)
	}
}

func TestCocoaPodsParser_PodfileLock_SourcePathIsSet(t *testing.T) {
	dir := t.TempDir()
	content := `PODS:
  - Alamofire (5.8.1)

DEPENDENCIES:
  - Alamofire
`
	writeTempFile(t, dir, "Podfile.lock", content)
	path := filepath.Join(dir, "Podfile.lock")

	p := &CocoaPodsParser{}
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

func TestCocoaPodsParser_Podfile_DoubleQuotes(t *testing.T) {
	dir := t.TempDir()
	content := `pod "Alamofire", "~> 5.8"
pod "SnapKit"
`
	writeTempFile(t, dir, "Podfile", content)

	p := &CocoaPodsParser{}
	deps, err := p.Parse(filepath.Join(dir, "Podfile"))
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
	if depMap["Alamofire"].Version != "~> 5.8" {
		t.Errorf("expected ~> 5.8, got %s", depMap["Alamofire"].Version)
	}
	if depMap["SnapKit"].Version != "*" {
		t.Errorf("expected *, got %s", depMap["SnapKit"].Version)
	}
}
