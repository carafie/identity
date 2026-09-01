## API Endpoints

- [`POST` `/auth/otps`](#post-authotps)
- [`POST` `/auth/otps/{id}`](#post-authotpsid)
- [`POST` `/auth/tokens/refresh`](#post-authtokensrefresh)
- [`GET` `/auth/tokens`](#get-authtokens)
- [`DELETE` `/auth/tokens/{id}`](#delete-authtokensid)
- [`DELETE` `/auth/users/{id}`](#delete-authusersid)

<br><br>

### `POST` `/auth/otps`

Requests a new OTP code.

#### Request:

```http
Content-Type: application/json
```

```json
{ "email": "user@example.org" }
```

#### Response:

```http
HTTP/1.1 201 Created
Content-Type: application/json
```

```json
{ "id": "019fdb9f-1c1d-708e-b4ad-f3d019276c5b", "expires_at": "2026-12-25T18:45:59Z" }
```

#### Errors:

| Cause                     | Status Code               |
| ------------------------- | ------------------------- |
| Unexpected request format | 400 Bad Request           |
| Invalid email address     | 422 Unprocessable Content |

<br><br>

### `POST` `/auth/otps/{id}`

Confirms an OTP code.

#### Request:

```http
Content-Type: application/json
```

```json
{ "code": "123456" }
```

#### Response:

```http
HTTP/1.1 201 Created
Content-Type: application/json
Set-Cookie: refresh_token=ey...; Path=/auth/tokens/refresh; ...
```

```json
{ "access_token": "ey..." }
```

#### Errors:

| Cause                                              | Status Code               |
| -------------------------------------------------- | ------------------------- |
| Unexpected request format                          | 400 Bad Request           |
| Invalid or mismatched code                         | 422 Unprocessable Content |
| Not found or expired code, or max attempts reached | 404 Not Found             |

<br><br>

### `POST` `/auth/tokens/refresh`

Refreshes an access token.

#### Request:

```http
Cookie: refresh_token=ey...; ...
```

#### Response:

```http
HTTP/1.1 201 Created
Content-Type: application/json
```

```json
{ "access_token": "ey..." }
```

#### Errors:

| Cause                            | Status Code      |
| -------------------------------- | ---------------- |
| Invalid or expired refresh token | 401 Unauthorized |

<br><br>

### `GET` `/auth/tokens`

Lists all active refresh tokens.

#### Request:

```http
Authorization: Bearer ey...
```

#### Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
```

```json
[
  {
    "id": "019fe6ce-e25e-71fd-bd7d-9b0ae97c9179",
    "created_at": "2026-12-25T18:45:59Z",
    "expires_at": "2026-12-25T18:45:59Z"
  }
  // ...
]
```

#### Errors:

| Cause                           | Status Code      |
| ------------------------------- | ---------------- |
| Invalid or expired access token | 401 Unauthorized |

<br><br>

### `DELETE` `/auth/tokens/{id}`

Deletes a refresh token.

#### Request:

```http
Authorization: Bearer ey...
```

#### Response:

```http
HTTP/1.1 204 No Content
```

#### Errors:

| Cause                           | Status Code      |
| ------------------------------- | ---------------- |
| Unexpected request format       | 400 Bad Request  |
| Invalid or expired access token | 401 Unauthorized |

<br><br>

### `DELETE` `/auth/users/{id}`

Deletes a user.

#### Request:

```http
Authorization: Bearer ey...
```

#### Response:

```http
HTTP/1.1 204 No Content
```

#### Errors:

| Cause                           | Status Code      |
| ------------------------------- | ---------------- |
| Unexpected request format       | 400 Bad Request  |
| Invalid or expired access token | 401 Unauthorized |
