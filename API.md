## API Endpoints

- [`POST` `/auth/otps`](#post-authotps)
- [`POST` `/auth/otps/{id}`](#post-authotpsid)

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
Set-Cookie: refresh_token=ey...; Path=/auth/tokens/refresh; Max-Age=7776000; Secure; HttpOnly; SameSite=Lax
```

```json
{ "access_token": "ey..." }
```

#### Errors:

| Cause                                            | Status Code               |
| ------------------------------------------------ | ------------------------- |
| Unexpected request format                        | 400 Bad Request           |
| Invalid id or code, or mismatched code           | 422 Unprocessable Content |
| Code not found, expired, or max attempts reached | 404 Not Found             |
