## API Endpoints

- [`POST` `/auth/otps`](#post-authotps)
- [`POST` `/auth/otps/{id}`](#post-authotpsid)
- [`POST` `/auth/tokens/refresh`](#post-authtokensrefresh)

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
{ "id": "019fdb9f-1c1d-708e-b4ad-f3d019276c5b", "expires_at": "2026-08-07T09:50:32Z" }
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
| Invalid id or code, or mismatched code             | 422 Unprocessable Content |
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

| Cause                                      | Status Code      |
| ------------------------------------------ | ---------------- |
| Invalid, expired, or revoked refresh token | 401 Unauthorized |
