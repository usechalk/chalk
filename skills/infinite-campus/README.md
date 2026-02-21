# Infinite Campus OneRoster API

## Overview

Infinite Campus is a K-12 Student Information System focused on district management. It provides student, staff, and enrollment data through a OneRoster 1.1 compliant REST API.

## Authentication

Infinite Campus uses **OAuth 2.0 Client Credentials** flow.

**Important**: The token URL is **NOT** derivable from the base URL. It must be configured separately.

- **Token URL**: Must be provided explicitly in configuration (varies per deployment)
- **Method**: `POST` with `grant_type=client_credentials`
- **Authorization**: HTTP Basic Auth header using `client_id:client_secret` (Base64-encoded)

Example token request:

```http
POST {token_url}
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
```

## API Base

```
{base_url}/api/ims/oneroster/v1p1
```

## Endpoints

| Endpoint            | Description                        |
|---------------------|------------------------------------|
| `/orgs`             | Schools and districts               |
| `/users`            | Students, teachers, and staff       |
| `/courses`          | Course catalog                      |
| `/classes`          | Class sections                      |
| `/enrollments`      | Student and teacher class membership|
| `/academicSessions` | Terms, semesters, school years      |
| `/demographics`     | Student demographic data            |

## Pagination

Infinite Campus uses limit/offset pagination:

```
GET /users?limit=100&offset=0
```

- Default and recommended page size: `100`
- To detect the last page, check if the returned array size is less than the `limit` value

## Known Quirks

- **Unsupported characters in names/codes**: The following characters may appear in names or codes and should be replaced with underscores: `` ` \ : * ? " < > | ' # , % & ``
- **Long org unit codes**: Org unit codes may exceed 50 characters. Truncate to 50 characters to avoid storage issues.
- **`tobedeleted` status records**: Some records may have a status of `tobedeleted`. These records need graceful handling — mark them as inactive rather than failing on unexpected status values.

## Deployment

- **Cloud-hosted**: Hosted by Infinite Campus (most common)
- **On-premise**: Some districts maintain self-hosted instances

## Configuration Example

```toml
[provider]
name = "infinite_campus"
base_url = "https://district.infinitecampus.com"
token_url = "https://district.infinitecampus.com/campus/oauth2/token"
client_id = "your-client-id"
client_secret = "your-client-secret"
page_size = 100
```

Note that `token_url` must be configured explicitly since it cannot be derived from `base_url`.
