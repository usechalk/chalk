# Skyward OneRoster API

## Overview

Skyward is a K-12 SIS/ERP system that provides student, staff, and enrollment data through a OneRoster 1.1 compliant REST API.

## Authentication

Skyward uses **OAuth 2.0 Client Credentials** flow.

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

Skyward uses limit/offset pagination:

```
GET /users?limit=100&offset=0
```

- Default and recommended page size: `100`
- To detect the last page, check if the returned array size is less than the `limit` value

## Known Quirks

- **Missing teacher identifiers**: Some teacher records may lack standard identifiers. Use `sourcedId` as a fallback identifier when other identifiers are absent.
- **Users missing names**: Some user records may be missing both first AND last name. These records should be skipped during sync rather than imported with empty names.
- **Inconsistent `tobedeleted` status handling**: The `tobedeleted` status may not be consistently applied across all record types. Implement defensive handling for unexpected status values.

## Deployment

- **Cloud-hosted**: Skyward hosts most deployments
- **On-premise**: Some districts maintain self-hosted instances

## Configuration Example

```toml
[provider]
name = "skyward"
base_url = "https://district.skyward.com"
token_url = "https://district.skyward.com/api/oauth/token"
client_id = "your-client-id"
client_secret = "your-client-secret"
page_size = 100
```

Note that `token_url` must be configured explicitly since it cannot be derived from `base_url`.
