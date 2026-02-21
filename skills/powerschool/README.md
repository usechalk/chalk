# PowerSchool OneRoster API

## Overview

PowerSchool is the most widely deployed K-12 Student Information System (SIS) in North America. It exposes student, staff, and enrollment data via a OneRoster 1.1 compliant REST API.

## Authentication

PowerSchool uses **OAuth 2.0 Client Credentials** flow.

- **Token URL**: Derived from the base URL: `{base_url}/oauth/access_token`
- **Method**: `POST` with `grant_type=client_credentials`
- **Authorization**: HTTP Basic Auth header using `client_id:client_secret` (Base64-encoded)

Example token request:

```http
POST {base_url}/oauth/access_token
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

PowerSchool uses limit/offset pagination:

```
GET /users?limit=100&offset=0
```

- Default and recommended page size: `100`
- To detect the last page, check if the returned array size is less than the `limit` value

## Known Quirks

- **Whitespace in sourced_ids**: Some `sourcedId` values may contain leading or trailing whitespace. Always trim these values before use.
- **Optional fields may be null**: Fields documented as optional in OneRoster may be returned as `null` rather than omitted entirely. Handle both cases.

## Deployment

- **SaaS**: Hosted by PowerSchool (most common)
- **On-premise**: Some districts run self-hosted instances

## Configuration Example

```toml
[provider]
name = "powerschool"
base_url = "https://district.powerschool.com"
client_id = "your-client-id"
client_secret = "your-client-secret"
page_size = 100
```

The `token_url` is automatically derived as `{base_url}/oauth/access_token` and does not need to be configured separately.
