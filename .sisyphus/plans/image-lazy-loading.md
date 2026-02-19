# Image Lazy-Loading: Strip Base64 at Tunnel Layer

## TL;DR

> **Quick Summary**: Strip base64 image data from message list responses at the tunnel-client layer, reducing 14MB+ network payloads to <100KB. Add GET part endpoint to server for on-demand image fetching. Update app to lazy-load images when clicked.
> 
> **Deliverables**:
> - Tunnel-client modification to strip `data:` URLs from FilePart
> - Server GET endpoint for individual part retrieval
> - App changes to fetch images on-demand via new API
> 
> **Estimated Effort**: Medium (3-4 hours)
> **Parallel Execution**: YES - 2 waves
> **Critical Path**: Task 1 (Server Endpoint) → Task 3 (App Integration) | Task 2 (Tunnel Stripping) parallel with Task 1

---

## Context

### Original Request
User reported 10s+ session creation times. Investigation revealed:
- Message list API returns 14.7MB+ responses due to base64 images in `FilePart.url`
- Network time: 30-50+ seconds for message loading
- Tunnel blocking delays other requests (like createSession)

### Interview Summary
**Key Discussions**:
- User already implemented "click to load" UI (buttons instead of inline images)
- Root cause is API response size, not rendering
- User agreed relay-layer solution is good approach
- Reduced preload from 5 to 2 sessions as temporary mitigation

**Research Findings**:
- `FilePart` structure: `{type: "file", mime, filename, url, id, sessionID, messageID}`
- `url` field contains `data:image/...;base64,...` (full image data)
- Server has DELETE and PATCH for parts, but NO GET endpoint
- App already shows image buttons that open preview modal on click

### Metis Review
**Identified Gaps** (addressed):
- **Missing GET endpoint**: Server lacks `GET /session/:sessionID/message/:messageID/part/:partID` - Added as Task 1
- **Backward compatibility**: Old apps would break if images always stripped - Using `lazy:` prefix to detect
- **Encryption interaction**: Stripping must happen before encryption at line 953 - Accounted for in Task 2
- **Non-image files**: Only strip `data:image/` URLs, preserve PDFs and external URLs

---

## Work Objectives

### Core Objective
Reduce message list API response size from 14MB+ to <100KB by stripping base64 image data at tunnel layer and loading images on-demand.

### Concrete Deliverables
1. `GET /session/:sessionID/message/:messageID/part/:partID` endpoint in opencode server
2. `stripBase64Images()` function in tunnel-client `main.go`
3. App integration to detect stripped URLs and fetch on-demand

### Definition of Done
- [ ] `curl /session/{id}/message` returns <100KB for sessions with images
- [ ] `curl /session/{id}/message/{mid}/part/{pid}` returns full FilePart with base64 URL
- [ ] App displays image buttons, clicking loads and shows image

### Must Have
- Strip ONLY `data:image/*` URLs (preserve PDFs, external URLs)
- Preserve all FilePart metadata: `id`, `mime`, `filename`, `sessionID`, `messageID`
- Replace stripped URL with `lazy:{partID}` marker for app detection
- Recalculate Content-Length header after stripping
- Handle encryption correctly (strip before encrypt)

### Must NOT Have (Guardrails)
- ❌ Add caching to tunnel-client
- ❌ Add compression to tunnel-client
- ❌ Modify message storage format in server
- ❌ Strip from single message endpoint (only message list)
- ❌ Strip from SSE events
- ❌ Add new dependencies to tunnel-client
- ❌ Change opencode server beyond adding GET endpoint

---

## Verification Strategy (MANDATORY)

> **UNIVERSAL RULE: ZERO HUMAN INTERVENTION**
>
> ALL tasks in this plan MUST be verifiable WITHOUT any human action.

### Test Decision
- **Infrastructure exists**: YES (Go tests in relay-server, bun test in opencode)
- **Automated tests**: Tests-after (verify functionality first, then add test if time)
- **Framework**: Go `testing` package for tunnel-client, `bun test` for server

### Agent-Executed QA Scenarios (MANDATORY — ALL tasks)

Verification tools by deliverable:
| Type | Tool | How Agent Verifies |
|------|------|-------------------|
| API/Backend | Bash (curl) | Send requests, parse responses, assert fields |
| Go code | Bash (go build/test) | Compile, run tests |
| App | Playwright (playwright skill) | Navigate, click, assert DOM |

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (Start Immediately):
├── Task 1: Add GET part endpoint to server (no dependencies)
└── Task 2: Implement image stripping in tunnel-client (no dependencies)

Wave 2 (After Wave 1):
└── Task 3: Update app to lazy-load images (depends: 1, 2)

Critical Path: Task 1 → Task 3
Parallel Speedup: ~30% faster than sequential
```

### Dependency Matrix

| Task | Depends On | Blocks | Can Parallelize With |
|------|------------|--------|---------------------|
| 1 | None | 3 | 2 |
| 2 | None | 3 | 1 |
| 3 | 1, 2 | None | None (final) |

### Agent Dispatch Summary

| Wave | Tasks | Recommended Agents |
|------|-------|-------------------|
| 1 | 1, 2 | task(category="quick", load_skills=[], run_in_background=true) for each |
| 2 | 3 | task(category="visual-engineering", load_skills=["playwright"], run_in_background=false) |

---

## TODOs

- [x] 1. Add GET Part Endpoint to OpenCode Server

  **What to do**:
  - Add `GET /session/:sessionID/message/:messageID/part/:partID` endpoint in `server.ts`
  - Return single `MessageV2.Part` matching the partID
  - Follow existing pattern from DELETE/PATCH endpoints (lines 1334-1400)
  - Add to SDK generation by running `./packages/sdk/js/script/build.ts`

  **Must NOT do**:
  - Modify existing DELETE/PATCH endpoints
  - Change MessageV2 or Part schema
  - Add authentication beyond existing session access

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Single file change, follows existing pattern, <30 min work
  - **Skills**: `[]`
    - No special skills needed, pure TypeScript/Hono API
  - **Skills Evaluated but Omitted**:
    - `playwright`: No browser testing needed for API endpoint

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Task 2)
  - **Blocks**: Task 3
  - **Blocked By**: None (can start immediately)

  **References** (CRITICAL - Be Exhaustive):

  **Pattern References** (existing code to follow):
  - `/Users/liuyao/Code/opencode-source/packages/opencode/src/server/server.ts:1334-1367` - DELETE part endpoint pattern (validator, params, async handler)
  - `/Users/liuyao/Code/opencode-source/packages/opencode/src/server/server.ts:1369-1400` - PATCH part endpoint pattern (similar structure)
  - `/Users/liuyao/Code/opencode-source/packages/opencode/src/server/server.ts:1321-1331` - GET single message pattern (returns MessageV2)

  **API/Type References** (contracts to implement against):
  - `/Users/liuyao/Code/opencode-source/packages/opencode/src/session/message-v2.ts` - MessageV2.Part schema definition
  - `/Users/liuyao/Code/opencode-source/packages/opencode/src/session/message-v2.ts:132-141` - FilePart definition with `url` field

  **Documentation References**:
  - `/Users/liuyao/Code/opencode-source/AGENTS.md` - SDK regeneration: `./packages/sdk/js/script/build.ts`

  **WHY Each Reference Matters**:
  - `server.ts:1334-1367`: Copy this exact pattern (describeRoute, validator, async handler) for new GET endpoint
  - `server.ts:1321-1331`: Shows how to return single entity (use same error handling)
  - `message-v2.ts`: Need to call `MessageV2.get()` then find specific part by ID

  **Acceptance Criteria**:

  **Agent-Executed QA Scenarios:**

  ```
  Scenario: GET part returns full FilePart with base64 URL
    Tool: Bash (curl)
    Preconditions: OpenCode server running on localhost:4096, session with image message exists
    Steps:
      1. Get a session ID: curl -s http://localhost:4096/session | jq -r '.[0].id'
      2. Get message list: curl -s http://localhost:4096/session/{sessionID}/message
      3. Find a message with file part: jq '.[].parts[] | select(.type == "file") | {messageID: .messageID, partID: .id}'
      4. Fetch single part: curl -s http://localhost:4096/session/{sessionID}/message/{messageID}/part/{partID}
      5. Assert: Response has `type: "file"`
      6. Assert: Response has `url` starting with `data:image/`
      7. Assert: Response has `mime`, `filename` or `id`
    Expected Result: Full FilePart returned with base64 data
    Evidence: Response body saved to /tmp/part-response.json

  Scenario: GET part returns 404 for non-existent part
    Tool: Bash (curl)
    Preconditions: OpenCode server running
    Steps:
      1. curl -s -w "%{http_code}" http://localhost:4096/session/test/message/test/part/nonexistent
      2. Assert: HTTP status is 404
    Expected Result: 404 Not Found
    Evidence: HTTP status code
  ```

  **Commit**: YES
  - Message: `feat(server): add GET endpoint for individual message parts`
  - Files: `packages/opencode/src/server/server.ts`, `packages/sdk/js/src/v2/gen/*`
  - Pre-commit: `bun run typecheck`

---

- [x] 2. Implement Image Stripping in Tunnel-Client

  **What to do**:
  - Add `stripBase64Images(body []byte, path string) ([]byte, error)` function in `main.go`
  - Detect message list response by path pattern `/session/[^/]+/message$`
  - Parse JSON as `[]map[string]interface{}`
  - For each message, iterate `parts` array
  - For parts with `type: "file"` and `url` starting with `data:image/`, replace `url` with `lazy:{partID}`
  - Re-serialize JSON
  - Call this function in `handleRequest()` at line 947, BEFORE encryption (before line 953)
  - Recalculate Content-Length header after stripping
  - Add timing log for stripping duration

  **Must NOT do**:
  - Add caching or compression
  - Strip from paths other than message list
  - Strip non-image data URIs (PDFs, etc.)
  - Strip external URLs (http/https)
  - Add new dependencies

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Single file, clear implementation, follows existing code patterns
  - **Skills**: `[]`
    - No special skills needed, pure Go implementation
  - **Skills Evaluated but Omitted**:
    - `git-master`: Simple commit, no complex git operations needed

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Task 1)
  - **Blocks**: Task 3
  - **Blocked By**: None (can start immediately)

  **References** (CRITICAL - Be Exhaustive):

  **Pattern References** (existing code to follow):
  - `/Users/liuyao/Code/opencode-relay-server/cmd/tunnel-client/main.go:916-991` - `handleRequest()` function where stripping will be inserted
  - `/Users/liuyao/Code/opencode-relay-server/cmd/tunnel-client/main.go:947` - `body, err := io.ReadAll(resp.Body)` - insertion point for stripping
  - `/Users/liuyao/Code/opencode-relay-server/cmd/tunnel-client/main.go:953-961` - Encryption happens AFTER, stripping must be BEFORE

  **API/Type References** (contracts to implement against):
  - Message structure: `{"info": {...}, "parts": [{"type": "file", "url": "data:image/...", "id": "partID", ...}]}`
  - App types at `/Users/liuyao/Code/opencode-anywhere/src/types/index.ts:60-84` - MessagePart interface

  **WHY Each Reference Matters**:
  - `main.go:947`: This is where body is read, strip IMMEDIATELY after
  - `main.go:953-961`: Must understand encryption flow to not break it
  - MessagePart interface: Understand exact field names to preserve

  **Acceptance Criteria**:

  **Agent-Executed QA Scenarios:**

  ```
  Scenario: Message list response has stripped image URLs
    Tool: Bash (curl + jq)
    Preconditions: Tunnel-client running, connected to OpenCode with session containing images
    Steps:
      1. curl -s http://relay-server/session/{sessionID}/message > /tmp/message-list.json
      2. jq '.[].parts[] | select(.type == "file") | .url' /tmp/message-list.json
      3. Assert: All URLs are "lazy:{partID}" format (not "data:image/")
      4. jq '.[].parts[] | select(.type == "file") | {id, mime, filename}' /tmp/message-list.json
      5. Assert: id, mime, filename are preserved (not null/empty)
      6. wc -c /tmp/message-list.json
      7. Assert: File size < 100KB (was 14MB+)
    Expected Result: Stripped response with lazy: URLs
    Evidence: /tmp/message-list.json, size comparison

  Scenario: Non-image file parts are not stripped
    Tool: Bash (curl + jq)
    Preconditions: Session has PDF attachment with data:application/pdf URL
    Steps:
      1. curl -s http://relay-server/session/{sessionID}/message | jq '.[].parts[] | select(.mime == "application/pdf") | .url'
      2. Assert: URL still starts with "data:application/pdf" (not stripped)
    Expected Result: PDF URLs preserved
    Evidence: Response showing full PDF URL

  Scenario: Text parts and tool invocations are unchanged
    Tool: Bash (curl + jq)
    Preconditions: Session has text messages and tool invocations
    Steps:
      1. curl -s http://relay-server/session/{sessionID}/message | jq '.[].parts[] | select(.type == "text")'
      2. Assert: Text content is present and unchanged
      3. curl -s http://relay-server/session/{sessionID}/message | jq '.[].parts[] | select(.type == "tool")'
      4. Assert: Tool invocations are present and complete
    Expected Result: Non-file parts unchanged
    Evidence: Response bodies

  Scenario: Code compiles and passes existing tests
    Tool: Bash (go build/test)
    Preconditions: In tunnel-client directory
    Steps:
      1. cd /Users/liuyao/Code/opencode-relay-server && go build ./cmd/tunnel-client
      2. Assert: Build succeeds with exit code 0
      3. go test ./... (if tests exist)
      4. Assert: Tests pass
    Expected Result: Clean build
    Evidence: Build output
  ```

  **Commit**: YES
  - Message: `perf(tunnel-client): strip base64 images from message list responses`
  - Files: `cmd/tunnel-client/main.go`
  - Pre-commit: `go build ./cmd/tunnel-client`

---

- [x] 3. Update App to Lazy-Load Images

  **What to do**:
  - Modify `MessageList.tsx` to detect `lazy:` prefix in FilePart URL
  - Add `fetchPartImage(sessionID, messageID, partID)` function to `opencode.ts`
  - When user clicks image button, check if URL is `lazy:{partID}`:
    - If yes: fetch via new GET part endpoint, cache result, then display
    - If no (already has data URL): display directly (backward compatible)
  - Show loading state while fetching image
  - Cache fetched images in memory (per-session Map)

  **Must NOT do**:
  - Persist images to local storage
  - Pre-fetch images automatically
  - Modify tunnel-client or server code
  - Change message structures in store

  **Recommended Agent Profile**:
  - **Category**: `visual-engineering`
    - Reason: React component changes, UI states, requires visual verification
  - **Skills**: `["playwright"]`
    - `playwright`: Need to verify click-to-load behavior in browser
  - **Skills Evaluated but Omitted**:
    - `frontend-ui-ux`: Not changing design, just adding loading state

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Sequential (Wave 2)
  - **Blocks**: None (final task)
  - **Blocked By**: Task 1, Task 2

  **References** (CRITICAL - Be Exhaustive):

  **Pattern References** (existing code to follow):
  - `/Users/liuyao/Code/opencode-anywhere/src/components/MessageList.tsx:638-654` - Current image button implementation
  - `/Users/liuyao/Code/opencode-anywhere/src/components/MessageList.tsx:680-685` - ImagePreviewModal usage
  - `/Users/liuyao/Code/opencode-anywhere/src/lib/opencode.ts:25-70` - `nativeFetch` pattern for API calls

  **API/Type References** (contracts to implement against):
  - `/Users/liuyao/Code/opencode-anywhere/src/types/index.ts:60-84` - MessagePart interface
  - New endpoint: `GET /session/:sessionID/message/:messageID/part/:partID` (from Task 1)

  **WHY Each Reference Matters**:
  - `MessageList.tsx:638-654`: This is where image buttons render, modify click handler
  - `MessageList.tsx:680-685`: ImagePreviewModal expects `imageUrl` string, need to pass fetched URL
  - `opencode.ts:25-70`: Follow same nativeFetch pattern for new API call

  **Acceptance Criteria**:

  **Agent-Executed QA Scenarios:**

  ```
  Scenario: Clicking image button fetches and displays stripped image
    Tool: Playwright (playwright skill)
    Preconditions: App running, tunnel-client stripping enabled, session with images
    Steps:
      1. Navigate to: http://localhost:3000
      2. Wait for: session list visible (timeout: 10s)
      3. Click: first session with images
      4. Wait for: message list loaded
      5. Find: button containing "Image 1"
      6. Click: button containing "Image 1"
      7. Wait for: .image-preview-modal or similar (timeout: 5s)
      8. Assert: img element inside modal has src starting with "data:image/"
      9. Screenshot: .sisyphus/evidence/task-3-image-loaded.png
    Expected Result: Image loads and displays in modal
    Evidence: .sisyphus/evidence/task-3-image-loaded.png

  Scenario: Loading state shown while fetching image
    Tool: Playwright (playwright skill)
    Preconditions: Slow network simulation or large image
    Steps:
      1. Navigate to session with images
      2. Click image button
      3. Assert: Loading indicator visible (spinner or text)
      4. Wait for: Image loaded
      5. Assert: Loading indicator gone, image visible
    Expected Result: User sees loading feedback
    Evidence: Screenshot during loading state

  Scenario: Backward compatible with existing data URLs
    Tool: Playwright (playwright skill)
    Preconditions: Message with non-stripped image URL (direct connection, not via tunnel)
    Steps:
      1. Connect app directly to OpenCode (bypass tunnel)
      2. Navigate to session with images
      3. Click image button
      4. Assert: Image displays immediately (no fetch needed)
    Expected Result: Direct URLs still work
    Evidence: Screenshot showing image
  ```

  **Commit**: YES (groups with final integration)
  - Message: `feat(app): lazy-load images via new part API endpoint`
  - Files: `src/components/MessageList.tsx`, `src/lib/opencode.ts`
  - Pre-commit: `npm run build` (or `bun build`)

---

## Commit Strategy

| After Task | Message | Files | Verification |
|------------|---------|-------|--------------|
| 1 | `feat(server): add GET endpoint for individual message parts` | server.ts, sdk/* | `bun run typecheck` |
| 2 | `perf(tunnel-client): strip base64 images from message list responses` | main.go | `go build` |
| 3 | `feat(app): lazy-load images via new part API endpoint` | MessageList.tsx, opencode.ts | `npm run build` |

---

## Success Criteria

### Verification Commands
```bash
# Before: Message list with images (should be 14MB+)
curl -s http://localhost:4096/session/{sessionID}/message | wc -c
# Expected: 14000000+ bytes

# After: Message list with stripped images (should be <100KB)
curl -s http://relay-server/session/{sessionID}/message | wc -c
# Expected: <100000 bytes

# Individual part fetch (should return full image)
curl -s http://localhost:4096/session/{sessionID}/message/{messageID}/part/{partID} | jq '.url' | head -c 50
# Expected: "data:image/png;base64,..."

# App builds without errors
cd /Users/liuyao/Code/opencode-anywhere && npm run build
# Expected: Build successful
```

### Final Checklist
- [ ] Message list API response < 100KB for sessions with images
- [ ] GET part endpoint returns full FilePart with base64 URL
- [ ] App displays image buttons that fetch and show images on click
- [ ] Backward compatible: direct data URLs still work
- [ ] No new dependencies added to tunnel-client
- [ ] All existing functionality preserved (text, tools, etc.)
