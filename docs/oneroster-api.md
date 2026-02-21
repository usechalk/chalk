# OneRoster REST API

Chalk exposes a read-only OneRoster 1.1 REST API at `/api/oneroster/v1p1/`.

## Base URL

```
http://localhost:8080/api/oneroster/v1p1
```

## Endpoints

### Users

```
GET /api/oneroster/v1p1/users
GET /api/oneroster/v1p1/users/{sourcedId}
```

**List response:**
```json
{
  "users": [
    {
      "sourcedId": "user-001",
      "status": "active",
      "dateLastModified": "2025-01-15T12:00:00Z",
      "username": "jdoe",
      "enabledUser": true,
      "givenName": "John",
      "familyName": "Doe",
      "role": "student",
      "email": "jdoe@example.com",
      "orgs": ["org-001"],
      "grades": ["09"]
    }
  ]
}
```

**Single response:**
```json
{
  "user": { ... }
}
```

### Orgs

```
GET /api/oneroster/v1p1/orgs
GET /api/oneroster/v1p1/orgs/{sourcedId}
```

### Courses

```
GET /api/oneroster/v1p1/courses
GET /api/oneroster/v1p1/courses/{sourcedId}
```

### Classes

```
GET /api/oneroster/v1p1/classes
GET /api/oneroster/v1p1/classes/{sourcedId}
```

### Enrollments

```
GET /api/oneroster/v1p1/enrollments
GET /api/oneroster/v1p1/enrollments/{sourcedId}
```

### Academic Sessions

```
GET /api/oneroster/v1p1/academicSessions
GET /api/oneroster/v1p1/academicSessions/{sourcedId}
```

### Demographics

```
GET /api/oneroster/v1p1/demographics
GET /api/oneroster/v1p1/demographics/{sourcedId}
```

## Response Format

All responses follow the OneRoster 1.1 JSON binding:

- **Collection endpoints** return `{ "<entityName>s": [...] }`
- **Single endpoints** return `{ "<entityName>": {...} }`
- **Not found** returns HTTP 404 with `{ "error": "not found" }`

## Authentication

The API is currently accessible without authentication when accessed from the console server. Future versions will support OAuth 2.0 bearer token authentication.

## Content Type

All responses use `application/json` with UTF-8 encoding.
