// Standalone walkthrough that mirrors marvin-sca's filter flow for one target.
//
// For each scenario it prints:
//   1. Fixture layout on disk
//   2. The raw lockfile `packages` entries (the GROUND TRUTH — what the lockfile actually says)
//   3. The IDEAL graph the lockfile implies (per-member edges intact)
//   4. The ACTUAL graph the autofix builder produces (after collapse)
//   5. Side-by-side diff: what got collapsed
//   6. Target manifest + computed seeds
//   7. Per-vuln walk trace — node lookup, isSeed check, ancestor walk, decision
//   8. The production filter's answer for confirmation
//
// Run with: go run /path/to/walkthrough/walk.go
// Must be invoked from a directory whose go.mod resolves the marvin-sca
// import (e.g. from inside a marvin-sca checkout). Fixture paths are
// resolved relative to this source file's location (via runtime.Caller),
// so the program works regardless of which cwd you invoke it from.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	at "github.com/DeepSourceCorp/artifacts/types"
	"github.com/DeepSourceCorp/marvin-sca/pkg/analyzer"
	"github.com/DeepSourceCorp/marvin-sca/pkg/autofix/npm"
	dg "github.com/DeepSourceCorp/marvin-sca/pkg/dependency-graph"
)

// repoRoot is the directory this walk.go file lives in, computed at startup.
// Using it for fixture paths makes the program work regardless of the cwd
// `go run` was invoked from (cwd needs to be inside a Go module for import
// resolution; that's a separate constraint from where the fixtures live).
var repoRoot = func() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(file)
}()

func main() {
	runScenario(
		"SCENARIO A — LEAK CASE (sibling pollution)",
		filepath.Join(repoRoot, "leak"),
		filepath.Join(repoRoot, "leak/packages/safe-app/package.json"),
		"lodash", "4.17.10",
		"expected: DROP (lodash belongs to vuln-app, not safe-app)",
	)

	fmt.Println("\n" + strings.Repeat("█", 88) + "\n")

	runScenario(
		"SCENARIO B — M3 CROSS-WORKSPACE TRANSITIVE",
		filepath.Join(repoRoot, "m3"),
		filepath.Join(repoRoot, "m3/packages/a/package.json"),
		"lodash", "4.17.10",
		"expected: KEEP (a → m3-b → lodash chain).  Reality: gets DROPPED ← the bug",
	)
}

// ---------------------------------------------------------------------------
// Scenario runner
// ---------------------------------------------------------------------------

func runScenario(label, root, manifest, vulnPkg, vulnVer, expectation string) {
	border := strings.Repeat("═", 88)
	fmt.Println(border)
	fmt.Printf("  %s\n", label)
	fmt.Printf("  %s\n", expectation)
	fmt.Println(border)

	section("1. FIXTURE LAYOUT ON DISK")
	printTree(root, "  ")

	section("2. WHAT THE LOCKFILE LITERALLY SAYS (ground truth)")
	printLockfilePackages(root + "/package-lock.json")

	section("3. EDGES THE LOCKFILE IMPLIES (the ideal graph — per-member edges)")
	printIdealTree(root)

	section("4. WHAT THE AUTOFIX BUILDER ACTUALLY PRODUCES")
	pm := npm.NewNPM(root + "/package.json")
	fmt.Printf("    NewNPM(rootManifest) — manifestFilePaths now lists every workspace member:\n")
	for _, p := range pm.ManifestFilePaths() {
		fmt.Printf("      • %s\n", strings.TrimPrefix(p, root+"/"))
	}
	graph, err := pm.BuildDependencyGraph(root+"/package-lock.json", root+"/package.json")
	if err != nil {
		fmt.Printf("    ERROR: %v\n", err)
		return
	}
	fmt.Println()
	fmt.Println("    Resulting graph (nodes + edges):")
	printGraph(graph, "      ")

	section("5. THE COLLAPSE — what changed between ideal and actual")
	explainCollapse(root, graph)

	section("6. TARGET AND SEEDS")
	target := at.SCATarget{
		Lockfile:       root + "/package-lock.json",
		Manifest:       manifest,
		Ecosystem:      "npm",
		PackageManager: "npm",
	}
	fmt.Printf("    target.manifest = %s\n", target.Manifest)
	deps := readDirectDeps(manifest)
	fmt.Printf("    manifest's direct deps (read from package.json): %v\n", sortedSet(deps))
	seeds := computeSeeds(graph, deps)
	fmt.Printf("    seeds (graph nodes that match those names): %v\n", sortedSet(seeds))

	section("7. TRACE THE WALK for vuln " + vulnPkg + "@" + vulnVer)
	traceWalk(graph, seeds, vulnPkg, vulnVer)

	section("8. PRODUCTION FILTER'S ANSWER (confirmation)")
	runProductionFilter(target, graph, vulnPkg, vulnVer)
}

// ---------------------------------------------------------------------------
// Visualization helpers
// ---------------------------------------------------------------------------

func section(s string) {
	fmt.Printf("\n  ── %s ──\n", s)
}

func printTree(dir, indent string) {
	entries, _ := os.ReadDir(dir)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if e.IsDir() {
			fmt.Printf("%s%s/\n", indent, e.Name())
			printTree(dir+"/"+e.Name(), indent+"  ")
		} else {
			fmt.Printf("%s%s\n", indent, e.Name())
		}
	}
}

func printLockfilePackages(lockfilePath string) {
	raw, _ := os.ReadFile(lockfilePath)
	var lock struct {
		Packages map[string]map[string]interface{} `json:"packages"`
	}
	_ = json.Unmarshal(raw, &lock)
	keys := sortedKeys(lock.Packages)
	for _, k := range keys {
		entry := lock.Packages[k]
		ver, _ := entry["version"].(string)
		name, _ := entry["name"].(string)
		deps, _ := entry["dependencies"].(map[string]interface{})
		link, _ := entry["link"].(bool)
		labelKey := k
		if labelKey == "" {
			labelKey = "<root>"
		}
		extras := []string{}
		if name != "" {
			extras = append(extras, "name="+name)
		}
		if ver != "" {
			extras = append(extras, "version="+ver)
		}
		if link {
			extras = append(extras, "(symlink, no deps info)")
		}
		if len(deps) > 0 {
			extras = append(extras, fmt.Sprintf("dependencies=%v", sortedKeysIface(deps)))
		}
		fmt.Printf("    Packages[%q]  %s\n", labelKey, strings.Join(extras, " "))
	}
}

func printIdealTree(root string) {
	// Re-parse the lockfile to derive the per-member dep relationships
	raw, _ := os.ReadFile(root + "/package-lock.json")
	var lock struct {
		Packages map[string]struct {
			Name         string            `json:"name"`
			Version      string            `json:"version"`
			Dependencies map[string]string `json:"dependencies"`
		} `json:"packages"`
	}
	_ = json.Unmarshal(raw, &lock)
	rootName := lock.Packages[""].Name
	if rootName == "" {
		rootName = "<root>"
	}
	fmt.Printf("    %s (workspace root)\n", rootName)

	// Find all workspace member paths
	var members []string
	for k := range lock.Packages {
		if k == "" {
			continue
		}
		if !strings.HasPrefix(k, "node_modules/") {
			members = append(members, k)
		}
	}
	sort.Strings(members)

	for _, m := range members {
		mPkg := lock.Packages[m]
		fmt.Printf("     ├── %s (%s)\n", mPkg.Name, m)
		depNames := sortedKeysStr(mPkg.Dependencies)
		for _, d := range depNames {
			ver := mPkg.Dependencies[d]
			fmt.Printf("     │     └── %s@%s\n", d, ver)
		}
	}
}

func printGraph(graph *dg.DependencyGraph, indent string) {
	var ids []string
	for id := range graph.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		n := graph.Nodes[id]
		var p, c []string
		for _, x := range n.Parents {
			p = append(p, x.Id)
		}
		for _, x := range n.Children {
			c = append(c, x.Id)
		}
		marker := "  "
		if len(p) == 0 && len(c) == 0 {
			marker = "⚠ "
		}
		fmt.Printf("%s%s%-30s parents=%v  children=%v\n", indent, marker, id, p, c)
	}
}

func explainCollapse(root string, graph *dg.DependencyGraph) {
	// Compare every dep-edge implied by the lockfile vs every dep-edge in the graph
	raw, _ := os.ReadFile(root + "/package-lock.json")
	var lock struct {
		Packages map[string]struct {
			Name         string            `json:"name"`
			Version      string            `json:"version"`
			Dependencies map[string]string `json:"dependencies"`
		} `json:"packages"`
	}
	_ = json.Unmarshal(raw, &lock)

	// Implied edges from per-member lockfile entries
	type edge struct{ from, to string }
	var implied []edge
	for k, pkg := range lock.Packages {
		if k == "" || strings.HasPrefix(k, "node_modules/") {
			continue
		}
		for dep := range pkg.Dependencies {
			implied = append(implied, edge{pkg.Name, dep})
		}
	}
	sort.Slice(implied, func(i, j int) bool {
		if implied[i].from == implied[j].from {
			return implied[i].to < implied[j].to
		}
		return implied[i].from < implied[j].from
	})

	// Actual edges in the graph
	type actualEdge struct{ from, to string }
	var actual []actualEdge
	for _, n := range graph.Nodes {
		for _, c := range n.Children {
			actual = append(actual, actualEdge{n.Name, c.Name})
		}
	}
	sort.Slice(actual, func(i, j int) bool {
		if actual[i].from == actual[j].from {
			return actual[i].to < actual[j].to
		}
		return actual[i].from < actual[j].from
	})

	fmt.Println("    Edges the LOCKFILE implies (per-member, the truth):")
	for _, e := range implied {
		fmt.Printf("      %s  →  %s\n", e.from, e.to)
	}
	fmt.Println("    Edges the GRAPH actually contains (post-collapse):")
	for _, e := range actual {
		fmt.Printf("      %s  →  %s\n", e.from, e.to)
	}
	fmt.Println("    ⇒ workspace-member parents got rewritten to the root project node.")
}

// ---------------------------------------------------------------------------
// Filter logic (mirror of pkg/analyzer/vuln_filter.go for instrumentation)
// ---------------------------------------------------------------------------

func readDirectDeps(manifestPath string) map[string]struct{} {
	raw, _ := os.ReadFile(manifestPath)
	var m struct {
		Dependencies     map[string]string `json:"dependencies"`
		DevDependencies  map[string]string `json:"devDependencies"`
		PeerDependencies map[string]string `json:"peerDependencies"`
	}
	_ = json.Unmarshal(raw, &m)
	out := make(map[string]struct{})
	for k := range m.Dependencies {
		out[k] = struct{}{}
	}
	for k := range m.DevDependencies {
		out[k] = struct{}{}
	}
	for k := range m.PeerDependencies {
		out[k] = struct{}{}
	}
	return out
}

func computeSeeds(graph *dg.DependencyGraph, depNames map[string]struct{}) map[string]struct{} {
	seeds := make(map[string]struct{})
	for _, node := range graph.Nodes {
		if _, want := depNames[node.Name]; want {
			seeds[node.Id] = struct{}{}
		}
	}
	return seeds
}

func traceWalk(graph *dg.DependencyGraph, seeds map[string]struct{}, vulnPkg, vulnVer string) {
	vulnID := vulnPkg + "@" + vulnVer

	fmt.Printf("    [step 1] look up graph.Nodes[%q]\n", vulnID)
	node, ok := graph.Nodes[vulnID]
	if !ok {
		fmt.Printf("              NOT in graph — filter keeps unknown vulns (safe default)\n")
		fmt.Printf("              decision: KEEP\n")
		return
	}
	fmt.Printf("              found ✓\n")

	fmt.Printf("    [step 2] isSeed(%q)?\n", vulnID)
	if _, isSeed := seeds[vulnID]; isSeed {
		fmt.Printf("              YES — vuln IS a direct dep of target's manifest\n")
		fmt.Printf("              decision: KEEP\n")
		return
	}
	fmt.Printf("              no (seeds = %v)\n", sortedSet(seeds))

	fmt.Printf("    [step 3] walk UP from %s through parents (GetAncestors):\n", vulnID)
	ancestors := dg.GetAncestors(node)
	// Manually narrate the parent walk
	narrateAncestorWalk(node, "              ", make(map[string]bool))

	fmt.Printf("              ancestors collected = %v\n", idsOf(ancestors))

	fmt.Printf("    [step 4] check each ancestor against seeds %v:\n", sortedSet(seeds))
	hit := ""
	for _, a := range ancestors {
		if _, isSeed := seeds[a.Id]; isSeed {
			hit = a.Id
			break
		}
	}
	if hit != "" {
		fmt.Printf("              %s IS in seeds → MATCH\n", hit)
		fmt.Printf("              decision: KEEP\n")
	} else {
		fmt.Printf("              no ancestor matched any seed\n")
		fmt.Printf("              decision: DROP\n")
	}
}

func narrateAncestorWalk(node *dg.DependencyNode, indent string, visited map[string]bool) {
	if visited[node.Id] {
		return
	}
	visited[node.Id] = true
	for _, parent := range node.Parents {
		hasGrandparent := len(parent.Parents) > 0
		if hasGrandparent {
			fmt.Printf("%s↑ %s (added to ancestors — has its own parents)\n", indent, parent.Id)
		} else {
			fmt.Printf("%s↑ %s (SKIPPED — no parents of its own, treated as project root)\n", indent, parent.Id)
		}
		narrateAncestorWalk(parent, indent+"  ", visited)
	}
}

func runProductionFilter(target at.SCATarget, graph *dg.DependencyGraph, vulnPkg, vulnVer string) {
	filter := analyzer.BuildWorkspaceVulnFilter(&target, graph)
	if filter == nil {
		fmt.Println("    filter is nil — fallback to master behavior (no scoping)")
		return
	}
	vuln := at.Vulnerability{Package: vulnPkg, Version: vulnVer}
	keep := filter(vuln)
	if keep {
		fmt.Printf("    BuildWorkspaceVulnFilter(...)(vuln=%s@%s) → KEEP\n", vulnPkg, vulnVer)
	} else {
		fmt.Printf("    BuildWorkspaceVulnFilter(...)(vuln=%s@%s) → DROP\n", vulnPkg, vulnVer)
	}
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

func sortedKeys(m map[string]map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysStr(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysIface(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedSet(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func idsOf(nodes []*dg.DependencyNode) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.Id)
	}
	return out
}
