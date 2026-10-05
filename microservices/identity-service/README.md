# identity-service

Identity Service ("Phòng quản lý nhân khẩu") — lưu thông tin đăng nhập người dùng. Spring Boot 3.5, Java 21, Gradle, PostgreSQL.

## Chạy nhanh

```bash
# 1. Khởi động PostgreSQL (tự tạo database identity_db) + Redis (6379)
docker compose up -d

# Hoặc nếu đã có PostgreSQL sẵn:
# psql -U postgres -c "CREATE DATABASE identity_db;"

# 2. Chạy service (port 8080)
./gradlew bootRun
```

Cấu hình DB trong `src/main/resources/application.yml` (override bằng biến môi trường `DB_USERNAME`, `DB_PASSWORD`).

## API

### POST /api/auth/register

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"bao","password":"123456"}'                       # role mặc định STUDENT
# hoặc -d '{"username":"thaygiao","password":"123456","role":"INSTRUCTOR"}'
```

- `201 Created` → `{"id":"<uuid>","username":"bao","role":"STUDENT"}`
- `409 Conflict` → username đã tồn tại
- `400 Bad Request` → dữ liệu không hợp lệ (kể cả `role` khác STUDENT/INSTRUCTOR — không tự đăng ký ADMIN được)

Kiểm tra mật khẩu đã được băm:

```sql
SELECT id, username, password, role FROM users;
-- password dạng $2a$10$...
```

### GET /api/auth/test-token?username={name}  (Bài 2)

```bash
curl "http://localhost:8080/api/auth/test-token?username=bao"
```

- `200 OK` → `{"token":"eyJhbGciOiJIUzI1NiJ9...","tokenType":"Bearer","expiresIn":900}`
- `404 Not Found` → user không tồn tại

Dán token vào https://jwt.io để xem 3 phần:

| Phần | Nội dung |
|------|----------|
| Header | `{"alg":"HS256"}` |
| Payload | `{"jti":"<uuid>","sub":"bao","role":"STUDENT","iat":...,"exp":...}` |
| Signature | `HMACSHA256(base64url(header) + "." + base64url(payload), app.jwt.secret)` |

Cấu hình trong `application.yml` dưới `app.jwt.*` (secret, access-token-expiration, refresh-token-expiration). Secret override bằng biến môi trường `JWT_SECRET`.

### POST /api/auth/login  (Bài 3)

```bash
curl -i -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"bao","password":"123456"}'
```

- `200 OK` → `{"accessToken":"eyJ...","refreshToken":"3f1c...-uuid","tokenType":"Bearer","expiresIn":900}`
- `401 Unauthorized` → `{"status":401,"message":"Bad credentials"}` (cả khi sai mật khẩu lẫn khi không có user)

Luồng xử lý (`AuthService.login`):
1. `userRepository.findByUsername(username)`
2. `passwordEncoder.matches(rawPassword, encodedPassword)` — không dùng `==`/`equals` vì BCrypt có salt ngẫu nhiên, mỗi lần `encode` cho ra chuỗi khác nhau.
3. Sai → `BadCredentialsException` → `GlobalExceptionHandler` trả 401 với thông báo chung.
   Nếu user không tồn tại vẫn chạy `matches` với một hash giả để thời gian phản hồi giống nhau (chống dò username).
4. Đúng → `JwtUtils.generateAccessToken(user)` + `RefreshTokenService.createRefreshToken(user.getId())`.

Stateless (`SecurityConfig`): `SessionCreationPolicy.STATELESS`, `NullSecurityContextRepository`, tắt `requestCache`/`formLogin`/`httpBasic`/`logout`.
Kiểm chứng: response đăng nhập (`curl -i`) **không có** header `Set-Cookie: JSESSIONID`.

### Access Token + Refresh Token  (Bài 5)

| | Access Token | Refresh Token |
|---|---|---|
| Dạng | JWT HS256 (`jti`, `sub`, `role`, `iat`, `exp`) | UUID ngẫu nhiên |
| Thời gian sống | 15 phút (`app.jwt.access-token-expiration`) | 7 ngày (`app.jwt.refresh-token-expiration`) |
| Lưu ở server | Không (stateless, tự kiểm bằng chữ ký) | Có, bảng `refresh_tokens` |
| Dùng để | Gọi API (`Authorization: Bearer ...`) | Gọi `/api/auth/refresh` lấy access token mới |
| Thu hồi | Không thu hồi được, chờ hết hạn | Xóa bản ghi trong DB |

Bảng `refresh_tokens`: `id`, `token` (unique), `expiry_date`, `user_id` (FK → `users.id`, `@ManyToOne` — mỗi lần đăng nhập/thiết bị một token).
`RefreshTokenRepository.findByToken` dùng `@EntityGraph("user")` để lấy luôn User sở hữu.

```sql
SELECT rt.id, rt.token, rt.expiry_date, rt.user_id, u.username
FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id;
```

### Refresh Token Rotation  (Bài 7)

`POST /api/auth/refresh` (permitAll) — body `{"refreshToken":"<uuid>"}`. Mỗi refresh token chỉ dùng được **1 lần**:

1. Tìm token trong DB (kèm User) → không có: **403** (token giả hoặc đã dùng)
2. Hết hạn → xóa khỏi DB, **403**
3. **Rotation:** `DELETE FROM refresh_tokens WHERE token = ?` → nếu 0 dòng bị xóa (request khác vừa dùng) → **403**
4. Tạo access token mới
5. Tạo refresh token mới (UUID mới, hạn 7 ngày)
6. Trả cặp mới `{accessToken, refreshToken, ...}`

Cả quy trình nằm trong 1 `@Transactional`: lỗi ở bước 4–5 thì việc xóa token cũ cũng rollback, người dùng không bị mất phiên.

```
Login            → A  + R1
refresh(R1)      → B  + R2     (R1 bị xóa)
refresh(R1)      → 403         (kẻ trộm / client cũ dùng lại R1)
refresh(R2)      → C  + R3
```

### Logout với Redis Blacklist  (Bài 8)

JWT là stateless nên không "xóa" được; muốn logout có hiệu lực ngay phải ghi lại token bị thu hồi.
Mỗi access token giờ có claim `jti` (UUID) làm định danh.

`POST /api/auth/logout` — **cần** `Authorization: Bearer <accessToken>`; body tùy chọn `{"refreshToken":"<uuid>"}`.

1. Giải mã token lấy `jti`, `exp`
2. `TTL = exp - now`
3. + 4. `SET blacklist:{jti} "revoked"` kèm TTL đó (1 lệnh, nguyên tử)
5. Nếu có gửi refreshToken (và nó thuộc user này) → xóa khỏi PostgreSQL

`JwtAuthenticationFilter` của identity-service kiểm tra chữ ký, `exp`, rồi `blacklist:{jti}` trong Redis → có thì **401**.
Khi TTL hết, Redis tự xóa key; lúc đó token cũng đã hết hạn tự nhiên nên blacklist không phình to.

```bash
docker exec -it identity-redis redis-cli
127.0.0.1:6379> KEYS *
1) "blacklist:5b1f0c2e-...-jti"
127.0.0.1:6379> TTL blacklist:5b1f0c2e-...-jti
(integer) 812          # = số giây còn lại của access token
127.0.0.1:6379> GET blacklist:5b1f0c2e-...-jti
"revoked"
```

### Postman

Import `postman/identity-service.postman_collection.json` → Run collection. Các request có sẵn test: 200 + JWT 3 phần + không có JSESSIONID, 401 khi sai mật khẩu, 401 khi user không tồn tại. Token đăng nhập được lưu vào biến `{{accessToken}}`.

## Nâng cấp từ bản dùng role USER

Role đổi thành `STUDENT` / `INSTRUCTOR` / `ADMIN`, claim đổi từ `roles: ["USER"]` thành `role: "STUDENT"`.
Hibernate 6 tạo CHECK constraint cho cột enum lúc tạo bảng, và `ddl-auto: update` **không** cập nhật constraint đó,
nên nếu bảng `users` đã có từ trước thì đăng ký STUDENT sẽ lỗi. Chọn 1 trong 2:

```bash
# Cách 1: xóa sạch DB để Hibernate tạo lại bảng
docker compose down -v && docker compose up -d
```
```sql
-- Cách 2: giữ dữ liệu
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
UPDATE users SET role = 'STUDENT' WHERE role = 'USER';
```
Token cũ (claim `roles`) sẽ không còn quyền gì — đăng nhập lại để lấy token mới.

## Cấu trúc

```
src/main/java/com/example/identityservice
├── IdentityServiceApplication.java
├── config/SecurityConfig.java        # SecurityFilterChain, csrf off, permitAll register, BCrypt bean
├── controller/AuthController.java    # register, login, test-token
├── dto/RegisterRequest, LoginRequest, UserResponse, TokenResponse
├── entity/User, Role, RefreshToken   # refresh_tokens.user_id -> users.id
├── exception/...                     # 409 / 400 handlers
├── repository/UserRepository, RefreshTokenRepository
├── security/JwtUtils.java            # generateAccessToken(User) (có jti), parseClaims(token)
├── security/JwtAuthenticationFilter  # verify JWT + kiểm tra blacklist Redis
├── service/AuthService.java          # register, login, refreshToken (rotation), logout
├── service/RefreshTokenService.java  # createRefreshToken(userId), verifyExpiration(token)
└── service/TokenBlacklistService    # Redis: blacklist:{jti} với TTL
```
