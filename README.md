# marvin-sca workspace walkthrough

Minimal, hand-rolled fixtures + a standalone Go program that demonstrate how an
SCA scanner's dependency graph behaves under different monorepo / workspace
shapes — and where it silently goes wrong.

## What's here

```
.
├── walk.go                       # standalone Go program: prints the lockfile ground
│                                   truth, the ideal graph, and the actual graph the
│                                   autofix builder produces, then walks the filter
│                                   decision for one vulnerability per scenario.
│
├── leak/                         # Scenario A — sibling pollution
│   ├── package.json              # workspace root (workspaces: ["packages/*"])
│   ├── package-lock.json         # shared lockfile carrying both members' deps
│   └── packages/
│       ├── safe-app/package.json # declares only dayjs (no vulnerable packages)
│       └── vuln-app/package.json # declares lodash@4.17.10 (vulnerable)
│
├── m3/                           # Scenario B — cross-workspace transitive
│   ├── package.json
│   ├── package-lock.json
│   └── packages/
│       ├── a/package.json        # declares dep on workspace sibling 'm3-b'
│       └── b/package.json        # declares lodash@4.17.10
│
└── research/                     # additional edge-case fixtures (single-repo,
                                   # custom layout, name collision, deep chain)
```

## What each scenario demonstrates

### Scenario A — Sibling pollution (`leak/`)

`safe-app` and `vuln-app` are two workspace members. `vuln-app` declares a
vulnerable `lodash`. A shared lockfile means an SCA scan of `safe-app` will
see `lodash` in the lockfile and may report it on the `safe-app` dashboard
even though `safe-app` doesn't depend on it.

**Expected outcome with a proper reachability filter**: `safe-app` reports
0 vulnerabilities; `vuln-app` reports the 9 lodash CVEs.

### Scenario B — Cross-workspace transitive (`m3/`)

`m3-a` legitimately depends on the workspace sibling `m3-b`, which transitively
brings in `lodash`. So `m3-a` genuinely has `lodash` as a transitive vuln
through `m3-b → lodash`.

**Expected outcome ideally**: `m3-a` reports the 9 lodash CVEs (legit
transitive). **Reality with the autofix builder's collapsed graph**: the
`m3-a → m3-b` and `m3-b → lodash` edges get rewritten as `m3-root → m3-b`
and `m3-root → lodash` (the autofix builder collapses workspace members onto
the root project node). The filter's ancestor walk can't trace `lodash` back
to `m3-b`, so the vuln gets dropped as a false negative.

Same code path as Scenario A; same graph shape; different ground truth →
opposite verdict (one correct, one wrong).

## Running it locally

Two ways to inspect the graph + filter behavior on these fixtures. Both
assume you have **the `marvin-sca` codebase checked out locally** (the
`debug` branch with the leak fix + TEMP DEBUG scaffolding).

Replace `<WALKTHROUGH>` and `<MARVIN_SCA>` below with your actual paths.

---

### Mode 1 — `walk.go` (standalone diagnostic, pretty trees + walk trace)

```bash
# From the marvin-sca checkout (gives the Go module context for the imports)
cd <MARVIN_SCA>
go run <WALKTHROUGH>/walk.go
```

Prints, for each scenario:

1. Fixture layout on disk
2. What the lockfile literally says (`packages["..."]` entries)
3. The ideal graph the lockfile implies (per-member edges intact)
4. The actual graph the autofix builder produces (post-collapse)
5. The collapse diff (lockfile edges vs graph edges)
6. The target manifest's direct deps + the computed seed set
7. A step-by-step walk trace for `lodash@4.17.10`
8. The production filter's confirmed verdict

### Mode 2 — run the actual `marvin-sca` binary against any fixture

Build once:

```bash
cd <MARVIN_SCA>
go build -o /tmp/marvin-sca ./cmd/
```

Then run against a fixture target (example: `leak/packages/safe-app`):

```bash
rm -rf /tmp/toolbox && mkdir -p /tmp/toolbox
cat > /tmp/toolbox/analysis_config.json <<EOF
{
  "sca_targets": [{
    "lockfile":        "<WALKTHROUGH>/leak/package-lock.json",
    "manifest":        "<WALKTHROUGH>/leak/packages/safe-app/package.json",
    "ecosystem":       "npm",
    "package_manager": "npm"
  }],
  "files": ["<WALKTHROUGH>/leak/packages/safe-app/package.json"]
}
EOF
TOOLBOX_PATH=/tmp/toolbox /tmp/marvin-sca 2>&1 | grep "TEMP DEBUG"
```

`TEMP DEBUG` lines are emitted from inside marvin-sca itself (via the
scaffolding in `pkg/analyzer/temp_debug_dump.go` on the `debug` branch).
You'll see:

- A full graph dump after `BuildDependencyGraph` (nodes with parents/
  children/IsDirect/IsDev/Constraint; orphan nodes marked with `⚠`).
- The seed set for the target.
- One line per vulnerability with the filter's KEEP / DROP decision and
  the reason (`IS a seed`, `walking ancestors → DROP`, etc.).

Repeat with any of the other fixture manifests by changing the `manifest`
field. Quick references:

| Scenario | Lockfile | Manifests |
|---|---|---|
| Sibling leak | `<WALKTHROUGH>/leak/package-lock.json` | `leak/packages/{safe-app,vuln-app}/package.json` |
| Cross-workspace transitive | `<WALKTHROUGH>/m3/package-lock.json` | `m3/packages/{a,b}/package.json` |
| Non-workspace single-repo | `<WALKTHROUGH>/research/single/package-lock.json` | `research/single/package.json` |
| Custom workspace layout (apps/*) | `<WALKTHROUGH>/research/custom-layout/package-lock.json` | `research/custom-layout/apps/{safe,vuln}/package.json` |
| Workspace-name collision | `<WALKTHROUGH>/research/collision/package-lock.json` | `research/collision/packages/consumer/package.json` |
| Deep chain (a → b → c → vuln) | `<WALKTHROUGH>/research/deep/package-lock.json` | `research/deep/packages/{a,b,c}/package.json` |

To see the slog signals from the filter alongside the TEMP DEBUG dumps,
drop the `| grep`:

```bash
TOOLBOX_PATH=/tmp/toolbox /tmp/marvin-sca 2>&1
```

By default marvin-sca runs at `slog.LevelWarn`, so the filter's INFO-level
signals (`Workspace target detected`, `Workspace scoping enabled`) won't
show. To see them, build with `slog.LevelInfo` in `<MARVIN_SCA>/cmd/main.go`
temporarily.

**Important — `walk.go` depends on the private `marvin-sca` Go module**
(`github.com/DeepSourceCorp/marvin-sca/pkg/analyzer` and friends). Outside the
DeepSource org, the program won't compile because those import paths aren't
public. The Go file is included here for *reference* and reproducibility within
the org — the fixtures themselves (package.json, package-lock.json) are
fully public and don't depend on anything.

If you want to reproduce the analysis without that module, the fixtures and
this README are sufficient to set up the experiment with any SCA tool that
parses npm workspaces.

## The lesson in one paragraph

Most npm-family SCA graph builders (npm v3, yarn, pnpm) were designed for
**autofix** purposes, not scoping. Autofix only needs to know "from any vuln,
what's *a* path back to the project so we can patch it?" — one root, many
paths down, sufficient. So when these builders process a workspace, they
collapse every workspace member's dep edges onto a single root project node.
That's fine for autofix but destroys the per-member structure a reachability
filter needs. A sub-target's filter walks `lodash → root` and gives up; the
edge `lodash → b → a` that would have proved the chain was thrown away.

The fix is to build a scoping-specific graph from the lockfile directly,
preserving per-member edges. cargo and bun already do this in marvin-sca;
extending the pattern to npm/yarn/pnpm is a separate follow-up.
