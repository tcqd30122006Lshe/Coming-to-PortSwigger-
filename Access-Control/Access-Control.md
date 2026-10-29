# Kiểm soát truy cập (Access Control) & Leo thang đặc quyền (Privilege Escalation)

> **Cre:** [https://portswigger.net/web-security/access-control](https://portswigger.net/web-security/access-control)

---

## 1. Kiểm soát truy cập (Access Control) là gì?

### 1.1. Định nghĩa
**Kiểm soát truy cập (Access Control)** — hay còn gọi là **Phân quyền (Authorization)** — là cơ chế áp dụng các ràng buộc đối với việc ai (hoặc cái gì) được phép thực hiện các hành động cụ thể hoặc truy cập vào các tài nguyên nhất định trên một hệ thống web.

Trong ngữ cảnh ứng dụng web, kiểm soát truy cập phụ thuộc chặt chẽ vào hai tiến trình đi trước:
*   **Xác thực (Authentication):** Xác minh danh tính người dùng (Người này là ai? Ví dụ: Đăng nhập bằng username/password).
*   **Quản lý phiên (Session Management):** Nhận diện các HTTP request tiếp theo thuộc về cùng một người dùng đã xác thực (Họ đang dùng phiên làm việc nào? Ví dụ: Session Cookie, JWT Token).
*   **Kiểm soát truy cập (Access Control):** Quyết định xem người dùng đó **có quyền** làm điều họ đang yêu cầu hay không (Họ có được phép xóa bài viết này, xem bảng lương kia, hay truy cập trang quản trị không?).

```
+-----------------------------------------------------------------------------------+
|                        MÔ HÌNH BẢO MẬT 3 TẦNG TRUY CẬP                            |
+-----------------------------------------------------------------------------------+
| 1. Authentication       | Bạn là ai? (Xác minh danh tính)                         |
| 2. Session Management   | Nhận diện các request tiếp theo của bạn (Duy trì phiên)  |
| 3. Access Control       | Bạn có ĐƯỢC PHÉP làm hành động này không? (Phân quyền)   |
+-----------------------------------------------------------------------------------+
```

### 1.2. Phân loại cơ chế kiểm soát truy cập

Theo góc nhìn thiết kế ứng dụng web, kiểm soát truy cập được chia thành **3 loại chính**:

#### A. Phân quyền dọc (Vertical Access Controls)
Ràng buộc quyền hạn giữa **các nhóm người dùng khác nhau về vai trò hoặc cấp bậc**.
*   *Ví dụ:* Người dùng thông thường (User) không được phép truy cập vào bảng điều khiển quản trị (Admin Panel), không được xóa tài khoản người khác hay cấu hình hệ thống.
*   *Lỗi phát sinh:* **Leo thang đặc quyền dọc (Vertical Privilege Escalation)** — khi User bình thường chiếm được quyền hạn của Admin.

#### B. Phân quyền ngang (Horizontal Access Controls)
Ràng buộc quyền hạn giữa **các người dùng có cùng cấp bậc/vai trò**, giới hạn họ chỉ được xem và sửa tài nguyên của chính mình.
*   *Ví dụ:* Khách hàng A chỉ được xem lịch sử đơn hàng và hóa đơn của khách hàng A, tuyệt đối không được xem hóa đơn của khách hàng B dù cả hai đều là User.
*   *Lỗi phát sinh:* **Leo thang đặc quyền ngang (Horizontal Privilege Escalation)** — thường được biết đến với tên gọi **IDOR (Insecure Direct Object References)**.

#### C. Phân quyền phụ thuộc ngữ cảnh (Context-dependent Access Controls)
Ràng buộc quyền hạn dựa trên **trạng thái hiện tại của quy trình nghiệp vụ** hoặc trình tự logic của ứng dụng.
*   *Ví dụ:* Người dùng không được phép bấm "Thanh toán thành công" khi chưa qua bước "Xác nhận giỏ hàng"; hoặc không thể tự ý sửa đơn hàng sau khi hàng đã xuất kho vận chuyển.

---

## 2. Vì sao lỗ hổng Broken Access Control tồn tại?

Theo bảng xếp hạng **OWASP Top 10 (2021 & hiện nay)**, **Broken Access Control (Kiểm soát truy cập bị phá vỡ)** đã vươn lên đứng ở **VỊ TRÍ SỐ 1** về mức độ phổ biến và rủi ro bảo mật trong các ứng dụng web.

Lỗ hổng này phát sinh do các nguyên nhân cốt lõi sau:

### 2.1. Sai sót logic nghiệp vụ ở tầng ứng dụng (Business Logic Flaws)
Không giống như SQLi hay XSS (có thể được quét tự động bằng chữ ký lỗi hoặc tường lửa WAF), các lỗi phân quyền nằm sâu trong **logic nghiệp vụ đặc thù** của từng ứng dụng. WAF không thể biết được `id=123` là của ai và liệu người gửi request có quyền sửa nó hay không. Lập trình viên phải tự viết code kiểm tra quyền, và chỉ cần quên kiểm tra ở một endpoint là lỗ hổng xuất hiện.

### 2.2. Sự tin tưởng mù quáng vào Client-side (Trusting the Client)
Ứng dụng ẩn nút bấm "Admin" trên giao diện HTML và lầm tưởng rằng người dùng không thấy nút thì sẽ không truy cập được. Kẻ tấn công chỉ cần dùng Burp Suite sửa URL hoặc gửi trực tiếp HTTP request tới endpoint ngầm.

### 2.3. Kiểm soát quyền phân mảnh, thiếu tập trung
Thay vì kiểm tra quyền ở một middleware tập trung (như Spring Security, Express Middleware), lập trình viên kiểm tra thủ công rải rác trong từng hàm controller. Khi hệ thống phình to lên hàng trăm API, việc bỏ sót kiểm tra quyền ở các API mới là điều không thể tránh khỏi.

---

## 3. Các dạng lỗ hổng Kiểm soát truy cập & Kỹ thuật khai thác

---

### 3.1. Leo thang đặc quyền dọc (Vertical Privilege Escalation)

Xảy ra khi người dùng cấp thấp có thể thực thi các chức năng dành riêng cho người dùng cấp cao hơn.

#### 📌 Dạng 1: Chức năng quản trị không được bảo vệ (Unprotected Admin Functionality)
Ứng dụng dựa vào việc "giấu kín" URL (Security through Obscurity) mà không hề có lớp kiểm tra quyền phía backend.

*   **Trường hợp 1A — URL quản trị dễ đoán:**
    *   Người dùng đăng nhập tài khoản thường, sau đó gõ thẳng vào thanh địa chỉ:
        ```text
        https://insecure-website.com/admin
        https://insecure-website.com/administrator
        ```
    *   Kiểm tra tệp tin `robots.txt` của trang web để tìm các đường dẫn bị cấm crawler nhưng không được phân quyền:
        ```text
        User-agent: *
        Disallow: /admin-panel
        ```
    *   🧪 **Lab:** [Unprotected admin functionality](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality)

*   **Trường hợp 1B — URL quản trị không thể đoán trước nhưng bị rò rỉ (Unpredictable URL):**
    *   Ứng dụng đặt tên trang quản trị ngẫu nhiên, ví dụ: `/admin-2a8b9c1d`.
    *   Tuy nhiên, lập trình viên lại nhúng đoạn mã JavaScript chứa URL này vào ngay trang chủ hoặc trang cá nhân:
        ```javascript
        <script>
            var isAdmin = false;
            if (isAdmin) {
                var adminLink = document.createElement('a');
                adminLink.href = '/admin-2a8b9c1d';
                adminLink.innerText = 'Trang Quản Trị';
                document.body.appendChild(adminLink);
            }
        </script>
        ```
    *   Kẻ tấn công chỉ cần bấm **F12 $\rightarrow$ View Source HTML/JS** là tìm ra đường dẫn bí mật để truy cập trực tiếp.
    *   🧪 **Lab:** [Unprotected admin functionality with unpredictable URL](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url)

---

#### 📌 Dạng 2: Phân quyền dựa trên tham số người dùng gửi lên (Parameter-based Access Control)
Ứng dụng xác định vai trò của người dùng dựa hoàn toàn vào dữ liệu do Client gửi lên trong Cookie hoặc HTTP Body.

*   **Trường hợp 2A — Cookie điều khiển quyền:**
    *   Khi người dùng đăng nhập, server trả về cookie:
        ```http
        Set-Cookie: role=user; session=abc123xyz
        hoặc
        Set-Cookie: Admin=false; session=abc123xyz
        ```
    *   Kẻ tấn công mở Burp Suite sửa lại cookie trước khi gửi đi:
        ```http
        Cookie: Admin=true; session=abc123xyz
        ```
    *   Nếu server chỉ đọc cookie này để cấp quyền mà không kiểm tra lại trong cơ sở dữ liệu, kẻ tấn công chiếm toàn quyền Admin.
    *   🧪 **Lab:** [User role controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter)

*   **Trường hợp 2B — Tham số trong Profile người dùng (Mass Assignment / Role Modification):**
    *   Khi cập nhật email, form chỉ hiển thị trường `email`, nhưng request gửi đi ở dạng JSON:
        ```json
        POST /my-account/change-email
        {
          "email": "user@target.com"
        }
        ```
    *   Kẻ tấn công thêm trường dữ liệu vai trò vào JSON payload:
        ```json
        POST /my-account/change-email
        {
          "email": "user@target.com",
          "roleid": 2
        }
        ```
    *   Hệ thống backend tự động mapping JSON vào User Entity trong DB mà không có whitelist trường cập nhật, nâng cấp tài khoản lên Admin.
    *   🧪 **Lab:** [User role can be modified in user profile](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile)

---

#### 📌 Dạng 3: Bỏ qua kiểm soát truy cập do cấu hình nền tảng / Routing (Platform Misconfigurations)

Nhiều hệ thống sử dụng một Reverse Proxy (như Nginx, Apache) đứng trước máy chủ Backend (như Spring Boot, Node.js). Proxy chặn truy cập vào `/admin`, nhưng cấu hình không đồng nhất giữa Proxy và Backend cho phép kẻ tấn công vượt mặt.

*   **Kỹ thuật 3A — Sử dụng Header ghi đè URL (`X-Original-URL` / `X-Rewrite-URL`):**
    *   Một số framework hỗ trợ các header này để định tuyến nội bộ:
        ```http
        GET / HTTP/1.1
        Host: vulnerable-website.com
        X-Original-URL: /admin/delete?username=carlos
        ```
    *   *Cơ chế:* Reverse Proxy thấy request gửi tới `/` nên cho phép đi qua. Khi đến backend framework, framework đọc `X-Original-URL` và thực thi lệnh xóa người dùng trên trang `/admin`.
    *   🧪 **Lab:** [URL-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented)

*   **Kỹ thuật 3B — Bỏ qua phân quyền dựa trên phương thức HTTP (Method-based Bypass):**
    *   Quy tắc bảo mật cấu hình chặn phương thức `POST /admin/upgrade-user`.
    *   Nhưng framework backend lại cho phép sử dụng phương thức `GET` thay thế, hoặc dùng header override:
        ```http
        GET /admin/upgrade-user?username=wiener&action=upgrade HTTP/1.1
        hoặc
        POST /admin/upgrade-user HTTP/1.1
        X-HTTP-Method-Override: GET
        ```
    *   Quy tắc chặn của Proxy chỉ áp dụng cho `POST`, nên request `GET` lọt qua và nâng quyền tài khoản thành công.
    *   🧪 **Lab:** [Method-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented)

---

### 3.2. Leo thang đặc quyền ngang (Horizontal Privilege Escalation) & IDOR

Xảy ra khi một người dùng có thể truy cập hoặc thao túng tài nguyên của người dùng khác có cùng cấp bậc quyền.

#### 📌 Dạng 4: Tham chiếu đối tượng trực tiếp không an toàn (IDOR - Insecure Direct Object References)
Ứng dụng sử dụng định danh người dùng do client cung cấp để truy vấn cơ sở dữ liệu mà không so sánh định danh đó với phiên đăng nhập hiện tại.

*   **Trường hợp 4A — ID tuần tự dễ đoán:**
    *   Khi xem thông tin tài khoản của mình (`wiener`), URL là:
        ```text
        GET /my-account?id=wiener
        hoặc
        GET /my-account?id=1001
        ```
    *   Kẻ tấn công sửa tham số thành:
        ```text
        GET /my-account?id=carlos
        hoặc
        GET /my-account?id=1002
        ```
    *   Hệ thống lập tức hiển thị thông tin nhạy cảm (API Key, địa chỉ, số điện thoại) của nạn nhân `carlos`.
    *   🧪 **Lab:** [User ID controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter)

*   **Trường hợp 4B — ID dạng GUID/UUID khó đoán nhưng bị lộ công khai:**
    *   Nếu ứng dụng dùng ID dạng chuỗi ngẫu nhiên khó đoán: `/my-account?id=c2a8f8b0-5f21-4a11-9e8c-8f1b2c3d4e5f`.
    *   Kẻ tấn công vào trang blog hoặc diễn đàn công khai, tìm bài đăng hoặc comment của nạn nhân `carlos`.
    *   Bấm F12 xem source code bài viết, phát hiện GUID của tác giả được nhúng sẵn trong thẻ:
        ```html
        <a href="/author-profile?id=c2a8f8b0-5f21-4a11-9e8c-8f1b2c3d4e5f">Carlos</a>
        ```
    *   Lấy GUID này lắp vào endpoint `/my-account?id=...` để chiếm thông tin tài khoản của `carlos`.
    *   🧪 **Lab:** [User ID controlled by request parameter, with unpredictable user IDs](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids)

*   **Trường hợp 4C — Tham chiếu file tĩnh trực tiếp (Static Files IDOR):**
    *   Ứng dụng cho phép tải lịch sử chat hoặc hóa đơn lưu trên ổ cứng:
        ```text
        GET /download-transcript/2.txt
        ```
    *   Thay đổi số `2.txt` thành `1.txt`, kẻ tấn công tải về toàn bộ nội dung cuộc trò chuyện riêng tư của khách hàng khác kèm mật khẩu họ vừa gửi cho nhân viên hỗ trợ.
    *   🧪 **Lab:** [Insecure direct object references](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references)

---

#### 📌 Dạng 5: Rò rỉ dữ liệu qua chuyển hướng (Data Leakage in Redirect)
Nhiều ứng dụng phát hiện người dùng không có quyền truy cập trang `/my-account?id=carlos` và lập tức gửi mã `HTTP 302 Found` để chuyển hướng người dùng về trang `/login`.

*   **Điểm yếu:** Lập trình viên phía backend quên gọi lệnh ngắt tiến trình (`return` hoặc `exit()`) sau khi đặt header redirect:
    ```php
    if ($user->id !== $_SESSION['user_id']) {
        header("Location: /login");
        // THIẾU LỆNH exit(); PHÍA SAU!
    }
    // MÃ PHÍA SAU VẪN TIẾP TỤC CHẠY VÀ IN DỮ LIỆU CỦA CARLOS RA BODY!
    echo renderAccountPage($user);
    ```
*   Trình duyệt thông thường sẽ tự động chuyển hướng và không hiển thị trang.
*   Nhưng khi bắt request bằng **Burp Suite Repeater**, kẻ tấn công thấy toàn bộ dữ liệu bí mật của nạn nhân vẫn nằm nguyên vẹn trong phần **Response Body** của gói tin HTTP 302!
*   🧪 **Lab:** [User ID controlled by request parameter with data leakage in redirect](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect)

---

#### 📌 Dạng 6: Rò rỉ mật khẩu trong trang quản lý tài khoản (Password Disclosure)
Khi truy cập trái phép vào trang cá nhân của nạn nhân qua IDOR (`/my-account?id=administrator`), trang web có thể tự động điền sẵn mật khẩu đã lưu của người dùng vào ô mật khẩu trong form HTML (`<input type="password" value="secret_password">`).
*   Bằng cách xem mã nguồn HTML (Page Source) hoặc bắt response trong Burp Suite, kẻ tấn công đọc được mật khẩu bản rõ của quản trị viên và đăng nhập chiếm quyền toàn bộ hệ thống.
*   🧪 **Lab:** [User ID controlled by request parameter with password disclosure](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure)

---

### 3.3. Leo thang từ Ngang sang Dọc (Horizontal to Vertical Privilege Escalation)

Kẻ tấn công thực hiện bước leo thang ngang trước để chiếm tài khoản của một người dùng khác, và người dùng đó tình cờ (hoặc cố ý) lại chính là **Quản trị viên (Administrator)**.

*   *Kịch bản:* Ứng dụng dính lỗi IDOR tại chức năng đổi mật khẩu hoặc cập nhật tài khoản:
    ```http
    POST /my-account/change-password
    Host: vulnerable.com
    
    username=administrator&new-password=hacked123
    ```
*   Kẻ tấn công đổi mật khẩu của tài khoản `administrator`, sau đó đăng nhập và đạt được quyền hạn quản trị cao nhất (Vertical Escalation).

---

### 3.4. Lỗ hổng trong quy trình nhiều bước (Multi-step Processes)

Nhiều nghiệp vụ quan trọng được chia thành nhiều bước:
1.  **Bước 1:** Chọn chức năng nâng quyền người dùng (`/admin/upgrade-user`).
2.  **Bước 2:** Xác nhận hành động (`/admin/upgrade-user-confirm?confirmed=true&username=wiener`).

*   *Lỗ hổng:* Lập trình viên kiểm tra quyền Admin rất kỹ ở **Bước 1**, nhưng chủ quan cho rằng người dùng chỉ có thể đến được **Bước 2** nếu đã đi qua Bước 1. Vì vậy, ở Bước 2, backend **hoàn toàn không kiểm tra quyền**.
*   *Khai thác:* Kẻ tấn công dùng tài khoản thường gửi thẳng request tới endpoint của Bước 2 và nâng quyền thành công.
*   🧪 **Lab:** [Multi-step process with no access control on one step](https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step)

---

### 3.5. Kiểm soát truy cập dựa trên Header Referer (Referer-based Access Control)

Ứng dụng kiểm tra quyền truy cập một chức năng nhạy cảm bằng cách đọc header `Referer` của trình duyệt:
*   Nếu `Referer` bắt đầu bằng `https://vulnerable-website.com/admin` $\rightarrow$ Cho phép truy cập.
*   *Lỗ hổng:* Header `Referer` do **trình duyệt của người dùng gửi lên**, kẻ tấn công có thể dùng Burp Suite sửa đổi header này tùy ý thành bất kỳ giá trị nào để vượt qua lớp kiểm tra.
*   🧪 **Lab:** [Referer-based access control](https://portswigger.net/web-security/access-control/lab-referer-based-access-control)

---

## 4. Cách phòng chống Broken Access Control triệt để

Lỗ hổng kiểm soát truy cập không thể phòng chống hoàn toàn bằng các thiết bị ngoại vi (WAF). Việc khắc phục phải được thực thi trực tiếp trong mã nguồn backend:

### 4.1. Nguyên tắc "Mặc định từ chối" (Deny by Default)
*   Mọi endpoint, tài nguyên và hành động trong hệ thống đều phải bị **chặn truy cập theo mặc định**.
*   Chỉ mở quyền truy cập cho những vai trò và người dùng được chỉ định rõ ràng trong danh sách trắng (Whitelist).

### 4.2. Cơ chế kiểm soát truy cập tập trung (Centralized Access Control)
*   Không viết logic kiểm tra quyền rải rác trong từng Controller hay Service.
*   Sử dụng middleware hoặc bộ lọc bảo mật tập trung của framework (ví dụ: Spring Security Filters, Express Middleware, Django Permissions) để kiểm tra phiên và vai trò ngay tại cửa ngõ vào ứng dụng.

### 4.3. Kiểm tra quyền ở tầng Model / Service (Model-level Authorization)
Khi người dùng yêu cầu thao tác trên một tài nguyên (ví dụ xem hóa đơn `invoice_id = 123`):
*   **SAI (Dễ dính IDOR):**
    ```sql
    -- Chỉ tìm theo ID do người dùng gửi lên
    SELECT * FROM invoices WHERE id = :invoice_id;
    ```
*   **ĐÚNG (Chống IDOR triệt để):**
    ```sql
    -- Ràng buộc bắt buộc ID tài nguyên phải thuộc về User đang đăng nhập trong Session
    SELECT * FROM invoices WHERE id = :invoice_id AND user_id = :session_user_id;
    ```
    Nếu bản ghi không tồn tại hoặc không thuộc về người dùng hiện tại, hệ thống lập tức trả về `403 Forbidden` hoặc `404 Not Found`.

### 4.4. Sử dụng mã định danh gián tiếp (Indirect Object References)
*   Thay vì để lộ ID khóa chính của Database (`id=1, 2, 3`), sử dụng các mã định danh ngẫu nhiên (UUID v4) hoặc lưu trữ một ánh xạ tạm thời (Map) trong Session của người dùng.
*   Ví dụ: Trong session của User, mảng hóa đơn có chỉ số `1, 2, 3` tương ứng với các hóa đơn của riêng họ. Khi client gửi `item=1`, server tra cứu trong session để lấy ra ID thật của DB.

### 4.5. Không bao giờ tin tưởng dữ liệu từ Client
*   Tuyệt đối không lưu quyền hạn (`isAdmin`, `role`) trong Cookie hay localStorage mà không được ký số bảo vệ (HMAC / Cryptographic Signature).
*   Không dựa vào các header HTTP dễ bị giả mạo như `Referer`, `X-Forwarded-For`, `X-Original-URL` để ra quyết định phân quyền.

---

### 4.6. So sánh mã nguồn: Dễ bị tổn thương (Vulnerable) vs An toàn (Secure)

#### ❌ Mã nguồn dễ bị tấn công (Vulnerable Code - Node.js / Express):
```javascript
// NGUY HIỂM: Nhận userId trực tiếp từ query params mà không đối chiếu với session!
app.get('/api/documents', async (req, res) => {
    const requestedUserId = req.query.userId;
    const docs = await Document.findAll({ where: { userId: requestedUserId } });
    res.json(docs);
});
```

#### ✅ Mã nguồn an toàn (Secure Code - Node.js / Express):
```javascript
// AN TOÀN: Luôn sử dụng userId từ phiên đăng nhập đã xác thực (req.session hoặc JWT)
app.get('/api/documents', authenticateSession, async (req, res) => {
    const authenticatedUserId = req.user.id; // Lấy từ token/session an toàn
    
    // Chỉ truy vấn tài nguyên thuộc về chính người dùng đang đăng nhập
    const docs = await Document.findAll({ where: { userId: authenticatedUserId } });
    res.json(docs);
});
```

---

## 5. Danh mục 13 bài Lab Access Control trên PortSwigger (Lộ trình luyện tập)

| STT | Tên bài Lab | Dạng lỗ hổng | Cấp độ |
| :---: | :--- | :--- | :---: |
| 1 | Unprotected admin functionality | Phân quyền dọc (URL dễ đoán) | Apprentice |
| 2 | Unprotected admin functionality with unpredictable URL | Phân quyền dọc (Lộ URL trong JS) | Apprentice |
| 3 | User role controlled by request parameter | Phân quyền dọc (Cookie điều khiển role) | Apprentice |
| 4 | User role can be modified in user profile | Phân quyền dọc (Mass Assignment qua JSON) | Practitioner |
| 5 | URL-based access control can be circumvented | Bypass cấu hình Proxy (`X-Original-URL`) | Practitioner |
| 6 | Method-based access control can be circumvented | Bypass phương thức HTTP (POST sang GET) | Practitioner |
| 7 | User ID controlled by request parameter | IDOR (Thay đổi ID tuần tự) | Apprentice |
| 8 | User ID controlled by request parameter, with unpredictable user IDs | IDOR (Tìm GUID nạn nhân bị lộ trên trang) | Practitioner |
| 9 | User ID controlled by request parameter with data leakage in redirect | IDOR (Đọc dữ liệu trong body HTTP 302) | Practitioner |
| 10 | User ID controlled by request parameter with password disclosure | IDOR (Lộ mật khẩu admin trong HTML) | Practitioner |
| 11 | Insecure direct object references | IDOR (Đọc file tĩnh chat transcript) | Practitioner |
| 12 | Multi-step process with no access control on one step | Logic nghiệp vụ (Bỏ qua bước xác nhận) | Practitioner |
| 13 | Referer-based access control | Phân quyền dựa trên Header `Referer` | Practitioner |

---
*Tài liệu học tập và thực hành bảo mật ứng dụng web - Biên soạn dựa trên tiêu chuẩn giáo trình PortSwigger Web Security Academy.*
