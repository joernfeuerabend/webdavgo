# Email-bound shares

## Lifecycle

1. A webdavgo user (the *owner*) calls `POST /api/v1/shares`, authenticated
   via Basic Auth with their webdavgo username and password.
2. The server generates a `shr_<16hex>` share ID and a `shr_tok_<64hex>` raw
   token (only SHA-256 hash stored). Both are returned **once** in the 201
   response.
3. The owner distributes the `share_url` (`/s/<share_id>/`) and `access_token`
   to the recipient through any out-of-band channel.
4. The recipient accesses the share via WebDAV at `/s/<share_id>/`, using
   Basic Auth with their email as username and the raw token as password.
5. The owner (or an admin via the admin UI) can delete the share at any time.
   The recipient's next request returns 401.

**Orphan shares**: if the owner deletes the shared directory after creating the
share, the recipient will receive 404 on PROPFIND of the share root. The share
row remains in the database until explicitly revoked.

## Create a share

```sh
curl -X POST http://localhost:8080/api/v1/shares \
     -u alice:alicepass1 \
     -H 'Content-Type: application/json' \
     -d '{
           "path": "/forms/birthday",
           "recipient_email": "bob@example.com",
           "permission": "read-write",
           "expires_at": null
         }'
```

Response (201):

```json
{
  "share_id": "shr_a1b2c3d4e5f60718",
  "owner_username": "alice",
  "path": "/forms/birthday",
  "recipient_email": "bob@example.com",
  "permission": "read-write",
  "access_token": "shr_tok_<64 hex chars>",
  "share_url": "/s/shr_a1b2c3d4e5f60718/",
  "created_at": "2026-06-04T10:00:00Z",
  "expires_at": null
}
```

`access_token` is only present in this 201 response. It is never returned again.

## List your shares

```sh
curl http://localhost:8080/api/v1/shares -u alice:alicepass1
```

## Get a specific share

```sh
curl http://localhost:8080/api/v1/shares/shr_a1b2c3d4e5f60718 -u alice:alicepass1
```

## Delete (revoke) a share

```sh
curl -X DELETE http://localhost:8080/api/v1/shares/shr_a1b2c3d4e5f60718 \
     -u alice:alicepass1
```

Returns 204. The recipient's next request returns 401.

## Access a share as the recipient

```sh
# PROPFIND (list directory)
curl -X PROPFIND \
     -u "bob@example.com:shr_tok_<64hex>" \
     -H "Depth: 1" \
     http://localhost:8080/s/shr_a1b2c3d4e5f60718/

# PUT (upload a file, requires read-write share)
curl -X PUT \
     -u "bob@example.com:shr_tok_<64hex>" \
     --data-binary @localfile.txt \
     http://localhost:8080/s/shr_a1b2c3d4e5f60718/localfile.txt

# SEARCH (find recently modified files)
curl -X SEARCH \
     -u "bob@example.com:shr_tok_<64hex>" \
     -H 'Content-Type: application/xml' \
     --data '<?xml version="1.0"?>
<d:searchrequest xmlns:d="DAV:">
  <d:basicsearch>
    <d:select><d:prop><d:displayname/></d:prop></d:select>
    <d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from>
    <d:where/>
  </d:basicsearch>
</d:searchrequest>' \
     http://localhost:8080/s/shr_a1b2c3d4e5f60718/
```

## Method gate inside a share

| Method               | read share | read-write share |
|----------------------|-----------|-----------------|
| OPTIONS, GET, HEAD   | ✓         | ✓               |
| PROPFIND, SEARCH     | ✓         | ✓               |
| PUT, DELETE, MKCOL   | 403       | ✓               |
| MOVE, COPY           | 403       | ✓ (within share only) |
| LOCK, UNLOCK         | 501       | 501             |

MOVE/COPY destinations must start with `/s/<same_share_id>/`. Cross-share or
absolute destinations return 403.

## Locks

Recipients cannot create, refresh or remove locks, but their writes respect
the owner's. A PUT, DELETE, MKCOL, MOVE, COPY or PROPPATCH through a share gets
`423 Locked` when its target (for MOVE and COPY also the destination) is
covered by a lock the owner holds on the user endpoint, the same as a write
without a lock token there. The share uses the owner's lock state, with the
share path translated, so a lock taken on an ancestor of the shared directory
counts too. A request with an `If` header gets `412 Precondition Failed`:
lock tokens are never accepted through a share.

OPTIONS on a share answers `DAV: 1`, not class 2. `DAV:supportedlock` and
`DAV:lockdiscovery` are returned empty in PROPFIND, so a recipient never sees
the owner's lock owners, tokens or lock roots.

## Admin UI

`/admin/shares` lists all shares across all owners with a **Revoke** button per
row. Revoked shares become immediately inaccessible (401 on next access).

`/admin/status` shows **Active shares: N**.
