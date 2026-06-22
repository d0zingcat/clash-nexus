# Loon Input Conversion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Convert Loon input to Clash/Mihomo YAML, Egern YAML, and Quantumult X configuration through every product entry point.

**Architecture:** Add a source-aware application service. A Loon parser produces the existing Clash-shaped intermediate map and warnings; existing Egern and QX converters consume it, while a new Clash target serializes it as YAML. Centralize source-target compatibility in the service so CLI, HTTP, subscriptions, and browser enforce it consistently.

**Tech Stack:** Go, yaml.v3, standard-library INI parsing, React 19, TypeScript, Vite.

---

### Task 1: Define source-aware conversion and the Clash target

**Files:**
- Create: converter/clashoutput/clash.go
- Create: converter/clashoutput/clash_test.go
- Modify: converter/converter.go
- Modify: internal/app/app.go
- Modify: internal/app/app_test.go

- [ ] Step 1: Write failing tests for source-aware conversion.

    func TestConvertLoonBytesToClash(t *testing.T) {
        result, err := NewService().ConvertBytesFrom("loon", "clash", []byte("[Rule]\\nFINAL,DIRECT\\n"))
        if err != nil { t.Fatalf("ConvertBytesFrom() error = %v", err) }
        if result.Target != "clash" || !strings.Contains(string(result.Content), "rules:") {
            t.Fatalf("unexpected result: %#v", result)
        }
    }

    func TestConvertBytesFromRejectsLoonToLoon(t *testing.T) {
        _, err := NewService().ConvertBytesFrom("loon", "loon", []byte("[Rule]\\nFINAL,DIRECT\\n"))
        if !errors.Is(err, ErrUnsupportedConversion) { t.Fatalf("error = %v", err) }
    }

- [ ] Step 2: Verify RED.

Run: go test ./internal/app -run 'TestConvert(LoonBytesToClash|BytesFromRejectsLoonToLoon)' -count=1
Expected: compile failure because ConvertBytesFrom does not exist.

- [ ] Step 3: Implement the minimal service and target.

Add ConvertBytesFrom(source, target string, data []byte), with empty source defaulting to clash; define ErrUnknownSource, ErrInvalidLoon, and ErrUnsupportedConversion; register clashoutput.New(). The target must return yaml.Marshal(config). Preserve ConvertBytes as the Clash-source compatibility wrapper.

- [ ] Step 4: Verify GREEN.

Run: go test ./internal/app -count=1

- [ ] Step 5: Commit.

Run: git add converter/converter.go converter/clashoutput internal/app/app.go internal/app/app_test.go
Run: git commit -m "feat: add source-aware conversion service"

### Task 2: Parse Loon into the Clash/Mihomo intermediate model

**Files:**
- Create: converter/looninput/loon.go
- Create: converter/looninput/loon_test.go

- [ ] Step 1: Write failing parser tests for Proxy, Proxy Group, Rule, Remote Rule, and unsupported sections.

    func TestParseBuildsClashModel(t *testing.T) {
        config, warnings, err := Parse([]byte("[Proxy]\\nHK = Shadowsocks, hk.example.com, 443, aes-128-gcm, password=secret\\n[Proxy Group]\\nProxy = select, HK, DIRECT\\n[Remote Rule]\\nhttps://example.com/rules.list, policy=Proxy, tag=Example\\n[Rule]\\nDOMAIN-SUFFIX,example.com,Proxy\\nFINAL,DIRECT\\n"))
        if err != nil { t.Fatal(err) }
        if len(clash.ToMapSlice(config["proxies"])) != 1 { t.Fatalf("proxies = %#v", config["proxies"]) }
        if len(clash.ToMapSlice(config["proxy-groups"])) != 1 { t.Fatalf("groups = %#v", config["proxy-groups"]) }
        if len(config["rules"].([]interface{})) != 3 { t.Fatalf("rules = %#v", config["rules"]) }
        if len(warnings) != 0 { t.Fatalf("warnings = %#v", warnings) }
    }

- [ ] Step 2: Verify RED.

Run: go test ./converter/looninput -count=1
Expected: package does not exist.

- [ ] Step 3: Implement Parse(data []byte) (map[string]interface{}, []string, error).

Use bufio.Scanner, section tracking, line-numbered errors, comment/blank-line skipping, and dedicated parseProxy, parseProxyGroup, parseRule, parseRemoteRule, and parseGeneral helpers. Map Loon Shadowsocks, ShadowsocksR, VMess, VLESS, Trojan, Hysteria, Hysteria2, and WireGuard into existing converter field names. Convert FINAL to MATCH. Make Remote Rule entries into named rule providers and RULE-SET entries. Emit a warning for every unsupported section or line; do not silently omit content.

- [ ] Step 4: Verify GREEN.

Run: gofmt -w converter/looninput/loon.go converter/looninput/loon_test.go
Run: go test ./converter/looninput -count=1

- [ ] Step 5: Commit.

Run: git add converter/looninput
Run: git commit -m "feat: parse Loon configs into Clash model"

### Task 3: Wire source through CLI and HTTP APIs

**Files:**
- Modify: main.go
- Modify: main_test.go
- Modify: internal/web/server.go
- Modify: internal/web/server_test.go

- [ ] Step 1: Write failing JSON, multipart, subscription, and CLI tests with source=loon.

Use a minimal Loon rule input. Assert target qx converts successfully. Assert subscription cache keys distinguish source. Extend normalizeFlagArgs coverage for -source loon.

- [ ] Step 2: Verify RED.

Run: go test ./internal/web ./ -run 'Test(ConvertJSONLoonToQX|ConvertFileLoonToEgern|SubscribeLoonSource|NormalizeFlagArgs)' -count=1

- [ ] Step 3: Implement propagation.

Add Source to convertRequest; read it from multipart forms, query parameters, and CLI -source; default it to clash; include it in subscription cache keys; call ConvertBytesFrom. Map unknown source, malformed Loon, and invalid source-target combinations to HTTP 400. Update CLI help and summaries.

- [ ] Step 4: Verify GREEN.

Run: go test ./internal/web ./ -count=1

- [ ] Step 5: Commit.

Run: git add main.go main_test.go internal/web/server.go internal/web/server_test.go
Run: git commit -m "feat: accept Loon source in CLI and API"

### Task 4: Add source selection to the web UI

**Files:**
- Modify: web/src/main.tsx
- Modify: README.md
- Modify: internal/web/static/index.html
- Modify: generated internal/web/static/assets files

- [ ] Step 1: Implement source state, target filtering, and request fields.

Define type Source = "clash" | "loon". Add an input-format selector. When Loon is selected, hide target loon, reset the target to an available selection, send source in JSON/multipart/subscription requests, use Loon labels/placeholders, and accept .conf files. Preserve the QX final-proxy-chain control.

- [ ] Step 2: Verify frontend build.

Run: pnpm run web:build

- [ ] Step 3: Document source=loon usage in CLI, API, subscription, and UI documentation, including warnings for unsupported Loon sections.

- [ ] Step 4: Rebuild generated embedded assets.

Run: pnpm run web:build

- [ ] Step 5: Commit.

Run: git add web/src/main.tsx internal/web/static README.md
Run: git commit -m "feat: add Loon input selection to web UI"

### Task 5: Full verification

- [ ] Step 1: Format modified Go source.

Run: gofmt -w main.go converter/converter.go converter/clashoutput/clash.go converter/looninput/loon.go internal/app/app.go internal/web/server.go

- [ ] Step 2: Run full Go suite.

Run: go test ./... -count=1

- [ ] Step 3: Build application.

Run: make build

- [ ] Step 4: Inspect final state.

Run: git diff --check
Run: git status --short

