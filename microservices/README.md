# Microservices demo

| Service | Port | Công nghệ | Vai trò |
|---------|------|-----------|---------|
| gateway-service | **8888** | Spring Cloud Gateway (WebFlux/Netty) + JJWT | Cổng vào duy nhất, định tuyến, verify JWT cho `/api/courses/**` |
| identity-service | 8080 | Spring Boot MVC + Security + JPA + PostgreSQL | Đăng ký / đăng nhập / cấp JWT (Bài 1–3) |
| course-service | 8083 | Spring Boot MVC + Security (không JJWT) | `/api/courses`, phân quyền `@PreAuthorize` từ header `X-User-Role` |
| product-service | 8082 | Spring Boot MVC + Security + JJWT | Resource Server: verify JWT, phân quyền `@PreAuthorize` (Bài 6) |

## Định tuyến (gateway-service/src/main/resources/application.yml)

| Client gọi Gateway | Predicate | Filter | Chuyển tiếp tới |
|--------------------|-----------|--------|-----------------|
| `:8888/identity/api/auth/login` | `Path=/identity/**` | `StripPrefix=1` | `:8080/api/auth/login` |
| `:8888/product/api/products` | `Path=/product/**` | `StripPrefix=1` | `:8082/api/products` |
| `:8888/api/courses/**` | `Path=/api/courses/**` | JWT GlobalFilter | `:8083/api/courses/**` (giữ nguyên path) |
| path khác | — | — | 404 tại Gateway |

`StripPrefix=1` bỏ đoạn path đầu tiên (`/identity`, `/product`) trước khi chuyển tiếp, nên service bên dưới không cần biết về tiền tố của Gateway.

## Chạy

```bash
cd identity-service && docker compose up -d && ./gradlew bootRun   # terminal 1
cd product-service  && ./gradlew bootRun                           # terminal 2
cd course-service   && ./gradlew bootRun                           # terminal 2b
cd gateway-service  && ./gradlew bootRun                           # terminal 3
```

## Kiểm tra

```bash
curl -X POST http://localhost:8888/identity/api/auth/register -H "Content-Type: application/json" -d '{"username":"bao","password":"123456"}'
curl -X POST http://localhost:8888/identity/api/auth/login    -H "Content-Type: application/json" -d '{"username":"bao","password":"123456"}'
TOKEN=<accessToken lấy từ login>
curl http://localhost:8888/product/api/products -H "Authorization: Bearer $TOKEN"
```

Hoặc import `postman/gateway.postman_collection.json` → Run collection (request Product dùng token lưu từ bước Login).
Log DEBUG của Gateway sẽ in route được khớp, ví dụ `Route matched: identity-service`.

## Bài 6 — Product-Service là Resource Server

```
Client ──Bearer JWT──► Gateway :8888 ──(giữ nguyên header Authorization)──► product-service :8082
                                                                              │
                                     JwtAuthenticationFilter (trước UsernamePasswordAuthenticationFilter)
                                       1. đọc "Authorization: Bearer <token>"
                                       2. verify chữ ký bằng app.jwt.secret (giống identity-service) + exp
                                       3. sub -> username, role "ADMIN" -> [ROLE_ADMIN]
                                       4. UsernamePasswordAuthenticationToken -> SecurityContextHolder
                                                                              │
                                     @PreAuthorize trên ProductController
```

product-service **không có DB user**, không gọi sang identity-service: chỉ tin vào chữ ký JWT.

| Endpoint | Quyền | Không token | Token STUDENT/INSTRUCTOR | Token ADMIN |
|----------|-------|-------------|------------|-------------|
| `GET /api/products` | `isAuthenticated()` | 401 | 200 | 200 |
| `DELETE /api/products/{id}` | `hasRole('ADMIN')` | 401 | **403** | **200** |

Token sai chữ ký / hết hạn → 401 ngay tại filter.

**Tài khoản ADMIN:** `/register` chỉ tạo `STUDENT`/`INSTRUCTOR`, nên identity-service tự tạo sẵn `admin` / `admin123` khi khởi động
(`AdminSeeder`, cấu hình `app.admin.*`, override bằng `ADMIN_USERNAME`/`ADMIN_PASSWORD`).
Hoặc nâng quyền user có sẵn: `UPDATE users SET role = 'ADMIN' WHERE username = 'bao';` rồi đăng nhập lại để lấy token mới.

**Kiểm thử:** import `postman/bai6-product-security.postman_collection.json` → Run.
Kịch bản 1 (STUDENT xóa → 403) là request 6, kịch bản 2 (ADMIN xóa → 200) là request 7.
Dữ liệu sản phẩm nằm trong bộ nhớ, khởi động lại product-service để có lại sản phẩm 1.

## Kiểm tra JWT tại Gateway — `/api/courses/**`

`gateway-service/.../filter/JwtAuthenticationGlobalFilter.java` (GlobalFilter, order -1):

```
Request ──► Gateway :8888
              │ path khớp app.gateway.secured-paths ?  ── không ──► forward bình thường
              │ có
              ├─ thiếu "Authorization: Bearer"      ──► 401 "Thiếu Access Token"
              ├─ exp đã qua (ExpiredJwtException)  ──► 401 "Access Token đã hết hạn"
              ├─ sai chữ ký / sai định dạng         ──► 401 "Access Token không hợp lệ"
              └─ hợp lệ: xóa X-User-* client gửi lên, gắn
                   X-User-Role: <role>   X-User-Name: <sub>
                                                     ──► course-service :8083
```

- Secret: `app.jwt.secret` trong gateway — **phải giống** identity-service.
- Các request bị chặn **không bao giờ tới** course-service.
- Gateway xóa mọi `X-User-Role`/`X-User-Name` do client tự gửi trước khi gắn giá trị thật → không giả mạo được role.
- course-service tin header do Gateway gắn ⇒ **không được mở port 8083 ra ngoài**, mọi truy cập phải đi qua Gateway.
- Gateway chưa kiểm tra blacklist Redis (Bài 8): token đã logout vẫn qua được Gateway tới khi hết hạn.

**Kiểm thử:** import `postman/gateway-jwt-courses.postman_collection.json` → Run.
Token hết hạn và token sai chữ ký được **tự ký trong pre-request script** (CryptoJS + secret dùng chung), không phải chờ 15 phút.

| # | Request | Mong đợi |
|---|---------|----------|
| 1 | GET không token | 401 tại Gateway |
| 2 | GET token hết hạn | 401 "hết hạn" |
| 3 | GET token ký bằng secret khác | 401 "không hợp lệ" |
| 4 | GET token STUDENT | 200, `currentUser.authorities = ["STUDENT"]` |
| 5 | Gửi kèm `X-User-Role: ADMIN` giả | vẫn nhận `STUDENT` |
| 6 / 7 | POST khóa học bằng STUDENT / INSTRUCTOR | **403** / 201 |
| 8 | GET token INSTRUCTOR | 200 |
| 9b | GET token ADMIN | 403 (ADMIN không nằm trong `STUDENT or INSTRUCTOR`) |
| 10 | Gọi thẳng `:8083` không header | 401 |

## Course-Service: Method Level Security từ header

course-service có `spring-boot-starter-security` nhưng **không có JJWT** — Gateway đã verify JWT, service chỉ tin header.

```
Gateway ──X-User-Role: STUDENT, X-User-Name: bao──► course-service
             GatewayHeaderAuthenticationFilter: authority = "STUDENT" (không tiền tố ROLE_)
             → UsernamePasswordAuthenticationToken → SecurityContextHolder
             → @PreAuthorize
```

| API | Quyền | STUDENT | INSTRUCTOR | Không header |
|-----|-------|---------|------------|--------------|
| `GET /api/courses` | `hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR')` | 200 | 200 | 401 |
| `POST /api/courses` | `hasAuthority('INSTRUCTOR')` | **403** | 201 | 401 |

Vì dùng `hasAuthority('STUDENT')` (không phải `hasRole`), filter gắn authority đúng bằng giá trị header, không thêm `ROLE_`.

## Ghi chú

- gateway-service **không** có `spring-boot-starter-web`: Gateway là ứng dụng reactive chạy trên Netty; nếu có Spring MVC trong classpath, ứng dụng sẽ báo lỗi và không khởi động được.
- gateway-service thêm JJWT 0.11.5 (thuần Java, chạy được trong WebFlux).
- gateway-service dùng Spring Boot 3.4.10 + Spring Cloud 2024.0.2 để giữ đúng tên `spring-cloud-starter-gateway` và prefix cấu hình `spring.cloud.gateway.routes`.
  (Từ Spring Cloud 2025.0 artifact được đổi thành `spring-cloud-starter-gateway-server-webflux` và prefix thành `spring.cloud.gateway.server.webflux.*`.)
