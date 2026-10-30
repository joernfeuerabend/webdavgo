# Clients

## File names and hrefs

Every `<d:href>` in PROPFIND and SEARCH responses, on the user endpoint and
under `/s/<share_id>/`, is a percent-encoded URI reference (RFC 4918 §8.3):
each path segment is encoded, `/` separators and the trailing `/` of a
collection are kept, and the result is XML-escaped (`&` → `&amp;`). A file
`Straße & „Plan“.txt` is listed as
`/Stra%C3%9Fe%20&amp;%20%E2%80%9EPlan%E2%80%9C.txt`. Clients can send an
href unchanged as the request path or `Destination` of GET, PUT, DELETE,
MOVE and COPY, and a collection href as the SEARCH scope.

**SEARCH scope.** The scope `<d:href>` is a URI reference (RFC 5323 §5.4,
RFC 3986 §4.1) and is percent-decoded. A query or fragment is ignored. The
scope resolves against the endpoint root: the user's root, or the share root
at `/s/<share_id>/`. At a share, a path starting with `/s/<share_id>` (as in
the share's own hrefs) is taken under that prefix. Any other path stays
relative to the share root, as Nextcloud-style clients expect. An absolute
URI (`http://host/...`) is accepted only when scheme and host match the
request.

| Scope | Answer |
|-------|--------|
| not a valid URI reference (e.g. a raw `100%` or `%#`) | 400 |
| does not exist, other scheme or host, or outside the share | 409 with `<d:error><d:search-scope-valid><d:response>` naming the scope with `404` (RFC 5323 §2.2.2) |
| not a collection | 400 |

The server does not normalize Unicode: it stores the bytes of the name the
client sends and returns exactly those bytes, percent-encoded. Depending on
the client, `ü` may arrive precomposed (NFC) or decomposed (NFD). On a Linux
filesystem the two forms are two different names. APFS treats them as the
same file.

## Conditional requests & ETags

Sync clients rely on these standard HTTP/WebDAV semantics. They apply equally
to the user endpoint and to share endpoints (`/s/<share_id>/`).

**ETag.** Every method reports the same strong ETag for a file: GET/HEAD and
PUT in the `ETag` header, PROPFIND and SEARCH as `getetag`. Format:
`"<mtime-unix-nanoseconds-hex><size-hex>"`, quoted, never `W/`. The ETag a
PUT returns can be sent unchanged as `If-Match` on the next request. Because
the tag uses the nanosecond mtime, it changes on every write even within the
same second on filesystems with sub-second timestamps (ext4, APFS, XFS). On
filesystems with coarse mtimes (FAT, some network filesystems) two writes of
the same size within one timestamp tick can produce the same ETag.

**Preconditions (RFC 9110 §13).**

| Header | Methods | Fails with 412 when |
|--------|---------|---------------------|
| `If-Match: "<etag>", …` | PUT, DELETE | the file is missing, or no listed tag strongly matches (weak `W/` tags never match) |
| `If-Match: *` | PUT, DELETE | the file is missing |
| `If-None-Match: "<etag>", …` | PUT | a listed tag matches the current ETag (weak comparison) |
| `If-None-Match: *` | PUT | the file exists (create-only upload) |

Check and write are atomic per file: concurrent writers with the same
`If-Match` get exactly one success and one 412. GET/HEAD support
`If-None-Match` and `If-Modified-Since` (→ 304).

**Atomic PUT.** The body is written to a temporary file
(`.webdavgo-tmp-*`) in the target directory and renamed over the target only
after the whole body arrived. An aborted upload leaves the previous content
untouched. Temporary files never appear in PROPFIND or SEARCH, and requests
addressing that prefix get 403. Status codes are unchanged: 201 on success
(create or overwrite), 409 when the parent collection is missing.

**401 vs 429 vs 503.** 401 means wrong or revoked credentials only. When the
database cannot be read during authentication, the server answers 503 with
`Retry-After: 30`. When the brute-force protection holds a client or an
account back, it answers 429 with `Retry-After`. Share recipients therefore
never mistake a server fault or a lockout for a revoked share.

**Download headers.** Every GET/HEAD (and POST, which x/net answers like
GET) of a stored file, on the user and on the share endpoint, carries
`Content-Disposition: attachment; filename*=UTF-8''<name>`,
`X-Content-Type-Options: nosniff` and
`Content-Security-Policy: default-src 'none'; sandbox`, so a browser saves an
uploaded HTML or SVG file instead of rendering it on the server's origin.
`Content-Type`, `ETag`, `Last-Modified`, `Content-Length` and range handling
are unchanged. Every response of the WebDAV listener, errors included,
carries `X-Frame-Options: DENY`.

## Storage quota

Every user has a quota in bytes. 0 means unlimited. New users get
`default_quota` (default 1 GB = 1,000,000,000 bytes, set on **Admin →
Settings → Users**, effective on Apply) unless the admin enters another
value. Changing it does not touch existing users. The admin sets the quota in GB
on **Admin → Users** (when adding a user, or per user with *Set quota*),
which also shows each user's usage and the totals: used by all users, and
size and free space of the filesystem holding the data directory.

Usage is the total size of the user's files. It is kept in the database,
updated with every write, and recounted from disk at every start, so a
counter that drifted is correct again after a restart.

| Request | Effect on usage |
|---------|-----------------|
| PUT | the growth: new size minus the size of the file it replaces |
| COPY | the size of the copied file or tree, minus what an overwritten destination held |
| MOVE | none, except that an overwritten destination is freed |
| DELETE | the size of the deleted file or tree is freed |

A write that would pass the quota gets `507 Insufficient Storage` with the
RFC 4331 `DAV:quota-not-exceeded` error body. With a `Content-Length` it is
refused before the body is read. A chunked upload stops as soon as it passes
the quota, and its partial file is removed. A user over quota can still
read, list, move, delete and overwrite with smaller content. Writes through
a share count against the share owner. Recipients have no quota of their
own.

PROPFIND on a collection returns `DAV:quota-available-bytes` and
`DAV:quota-used-bytes` (RFC 4331) when requested by name. They are not part
of `allprop`. For an unlimited user, `quota-available-bytes` is the free
space of the data filesystem. A share reports only `quota-available-bytes`,
the owner's remaining quota. `quota-used-bytes` is answered as not found
(404 propstat), since the owner's total usage is no business of the
recipient.

## PROPFIND request bodies

The same rules apply on the user endpoint and on shares.

| Body | Answer |
|------|--------|
| empty or only whitespace | 207, as `allprop` (RFC 4918 §9.1) |
| `prop` | 207 with the named properties |
| empty `prop` | 207, each response carries an empty `prop` with 200 OK |
| `allprop` | 207 with all properties except the quota properties |
| `allprop` and `include`, in either order | 207 with `allprop` and the included properties, for example the quota properties |
| `propname` | 207 with property names only |
| not well-formed XML, including content after the root element | 400 (RFC 4918 §8.2) |
| a namespace prefix bound to the empty string (`xmlns:bar=""`), or an undeclared prefix on an element or attribute name | 400 |
| an encoding that is unknown, or bytes that are not valid in it | 400 |
| root element other than `DAV:propfind` | 400 |
| none or several of `prop`, `allprop`, `propname`, or `include` without `allprop` | 400 |

Other elements, in `DAV:` or any other namespace, are ignored (RFC 4918 §17). A
400 has no XML body, and the reason is logged at Debug.

Besides UTF-8, a body can be UTF-16 with a byte order mark, or use any encoding
named in its XML declaration that `golang.org/x/net/html/charset` knows, for
example `ISO-8859-1`. A byte order mark takes precedence over the declaration.

An included property the server does not have is answered in a 404 propstat, the
same as one named in `prop`. A refused `Depth: infinity` (403) and a missing
resource (404) take precedence over a 400 for the body.

## PROPFIND with propname

`propname` returns the names of the properties a resource has, without values
(RFC 4918 §9.1), on the user endpoint and on shares. On a collection this
includes `quota-available-bytes` and, except on shares, `quota-used-bytes`
(RFC 4331 §2), although `allprop` leaves them out.

## Locks

The user endpoint is DAV class 2 and accepts exclusive and shared write locks
with Depth 0 or infinity (RFC 4918 §6, §9.10). Lock state lives in memory and is
lost on restart. For locks and shares, see [Shares](shares.md#locks).

**Creating a lock.** LOCK answers with a `Lock-Token` header holding a random
`urn:uuid` token and `DAV:lockdiscovery` in the body. An unmapped URL becomes an
empty resource (201), a missing parent gives 409. Without a `Timeout` header a
lock does not expire. A list of timeouts uses the first value understood, and
values above `Second-4294967295` are ignored. A LOCK without a body refreshes the
locks on the resource whose tokens are in a true list of the `If` header.

| LOCK result | Status |
|-------------|--------|
| conflict on the resource or an ancestor | 423 with `no-conflicting-lock` |
| Depth infinity with a conflicting lock on a member | 207: the member with 423, the request URI with 424 |
| a write is running on what the lock would cover | 503 with `Retry-After: 1`, without waiting |

A Depth 0 lock on a collection covers its properties and membership only (§7.4).
So of the writes below it, only one that adds, removes or renames a direct member
gets it 503, and overwriting a member does not.

**The `If` header** is evaluated as in RFC 4918 §10.4 on every method except
OPTIONS, SEARCH and UNLOCK: tagged and untagged lists, `Not`, state tokens and
entity tags with strong comparison. A tagged list applies only to its tagged
resource. A malformed header gives 400, and a header without a true list gives
412.

**Writes to locked resources.** PUT, DELETE, MKCOL, PROPPATCH, MOVE (source and
destination) and COPY (destination) need the token of a lock on the resource in a
true list, otherwise 423 with `lock-token-submitted`. With several shared locks on
a resource, one token is enough. A lock on a collection, of any depth, also
protects its list of members (§7.4), so adding or removing a member needs its
token, while overwriting a member does not. Replacing or removing a collection
with locked members needs their tokens as well: otherwise nothing changes and the
answer is 207, listing each locked member with 423. An `If` header that is true
without such a token still gives 423, which is what the litmus test
`cond_put_corrupt_token` expects.

**Locks and removed resources.** Locks at and below a resource that a successful
DELETE or MOVE removed, or that a COPY or MOVE overwrote, are gone. They do not
move with the resource. A moved or copied resource falls under a Depth infinity
lock of its new parent.

**Concurrent requests.** One token can be used by parallel requests. Writes to the
same path wait for each other instead of failing, on the user endpoint and on
shares together, so 423 always means a lock created by LOCK.

**Properties.** PROPFIND returns `DAV:supportedlock` and `DAV:lockdiscovery`
(RFC 4918 §15), by name and in `allprop`. They are not part of SEARCH responses.
`lockdiscovery` lists all locks that apply to the resource, including those
inherited from an ancestor locked with Depth infinity, with the remaining
timeout. The owner element keeps the namespaces it had in the LOCK request.

## SEARCH ordering and limits

`getlastmodified` is an HTTP-date (`Fri, 16 Oct 2026 12:00:00 GMT`). Date
literals in `<d:where>` may use that form, RFC 1123 with a numeric zone
(`date -uR`), or RFC 3339, and are compared at whole-second granularity.

The SEARCH response carries a `Date` header taken **before** the tree walk,
so `Date - 1 s` is a safe watermark for the next `getlastmodified > T` query.

```xml
<d:orderby>
  <d:order><d:prop><d:getlastmodified/></d:prop><d:ascending/></d:order>
</d:orderby>
<d:limit><d:nresults>100</d:nresults></d:limit>
```

- Sortable properties: `getlastmodified`, `creationdate`, `getcontentlength`,
  `displayname`, `getcontenttype`, `getetag` (strings compare ASCII
  case-insensitively). Others → 400.
- Default direction is ascending. Earlier `<d:order>` elements take
  precedence, and ties are broken by href. A missing value sorts as the lowest
  value.
- Without `<d:orderby>`, results are sorted by href.
- `nresults` must be a positive integer (else 400). The first N results after
  sorting are returned.
