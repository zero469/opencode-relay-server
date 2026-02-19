# Learnings

## 2026-02-17 Session Start
- Plan: image-lazy-loading
- Goal: Reduce message list API from 14MB+ to <100KB by stripping base64 images


## stripBase64Images Implementation (Wave 1)

### Patterns
- Endpoint detection via regex: `/session/[^/]+/message$`
- JSON parsing as `[]map[string]interface{}` for flexible message handling
- Parts array iteration with type assertions for each field

### Key Decisions
- URL replacement format: `lazy:{partID}` (app will parse to fetch on-demand)
- Only strips `data:image/*` URLs, preserves PDFs (`data:application/pdf`) and external URLs
- Strip BEFORE encryption in handleRequest() flow
- Added timing log for performance monitoring

### Integration Point
- Insert after `io.ReadAll(resp.Body)` in handleRequest()
- Before encryption block
- Content-Length header recalculation happens automatically at line 969

## App Lazy-Loading Implementation (Wave 3)

### Files Modified
- `src/lib/opencode.ts`: Added `fetchPartImage()` function and URL mapping
- `src/components/MessageList.tsx`: Added lazy-loading handler with cache
- `src/app/api/opencode/sessions/[id]/messages/[messageId]/parts/[partId]/route.ts`: New API route

### Key Patterns
- URL mapping in `getApiUrl()` uses regex replacement for web mode proxy
- Native mode uses direct URL construction with `${getBaseUrl()}${path}`
- Image cache uses `useRef<Map>` to avoid re-renders on cache updates
- Loading state uses `useState<Set<string>>` with partId as key

### Implementation Details
- `lazy:` prefix detection: `part.url?.startsWith('lazy:')`
- PartID extraction: `part.url.slice(5)`
- Cache key format: `${sessionID}:${messageID}:${partId}`
- Button shows spinner SVG and "Loading..." text while fetching

### Backward Compatibility
- Non-lazy URLs (existing `data:` URLs) pass through directly to `setPreviewImage`
- No changes to existing image preview modal behavior
## Image Caching & Lazy-Image Endpoint (Wave 2)

### Implementation Pattern
- Global cache: `var imageCache sync.Map` for thread-safe concurrent access
- Cache storage: `imageCache.Store(partID, url)` BEFORE replacing with `lazy:`
- No separate HTTP server needed - intercept in `handleRequest()` for `/lazy-image/` paths

### Key Files Modified
- `/cmd/tunnel-client/main.go`:
  - Added `imageCache sync.Map` at package level (line ~128)
  - Modified `stripBase64Images()` to cache images before stripping
  - Added `handleLazyImage()` method to serve cached images
  - Added path interception in `handleRequest()` for `/lazy-image/` prefix

### Handler Flow
1. Extract partID from path: `strings.TrimPrefix(req.Path, "/lazy-image/")`
2. Load from cache: `imageCache.Load(partID)`
3. Return 404 if not found with JSON error
4. Return JSON `{"url": "data:image/..."}` with Content-Type application/json
5. Apply encryption if configured (same pattern as other responses)

### No Eviction Policy
- Cache grows unbounded until process restart
- Simple design per requirements - no TTL or LRU

## Lazy Image Loading in opencode-anywhere (Client Implementation)

### Key Implementation Details

1. **Module-level cache** in MessageList.tsx (`lazyImageCache = new Map<string, string>()`) for image persistence across re-renders

2. **URL pattern detection**: `lazy:` prefix indicates lazy-loaded image, partID extracted via `url.slice(5)`

3. **Web vs Native mode** handled in `getApiUrl()` with regex replacement:
   - Native: `${getBaseUrl()}/lazy-image/${partId}` (direct to relay)
   - Web: `/api/opencode/lazy-image/${partId}` (proxy route)

4. **Loading state pattern**: `useState<Set<string>>` with partId as key, enables per-button loading indicators

5. **Proxy route structure**: `/api/opencode/lazy-image/[partId]/route.ts` follows existing session route pattern with:
   - `getAuthHeaders()` extracting `x-opencode-auth`
   - `getBaseUrl()` reading `x-opencode-url` header

6. **Button UX**: Disabled during load, spinner animation, "Loading..." text
