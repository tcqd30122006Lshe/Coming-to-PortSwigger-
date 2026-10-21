# BÁO CÁO BÀI TẬP: PHẦN B — XSS (TUẦN 9)
## BÀI THỰC HÀNH: DOM-BASED CROSS-SITE SCRIPTING (DOM XSS)

* **Tên bài Lab:** DOM XSS in `document.write` sink using source `location.search`
* **Nền tảng thực hành:** PortSwigger Web Security Academy
* **Link Lab:** [https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink)
* **Phân loại:** DOM-based Cross-Site Scripting (DOM XSS)

---

### 1. Lỗ hổng là gì?

Đây là lỗ hổng **DOM-based Cross-Site Scripting (DOM XSS)** xảy ra tại chức năng theo dõi tìm kiếm (Tracking Search) của ứng dụng web.

* **Bản chất:** Khác với Reflected hay Stored XSS (mã độc đi qua server backend), lỗ hổng này xảy ra **hoàn toàn ở phía Client-side (trình duyệt của người dùng)**.
* **Cơ chế hoạt động:** 
  * Trang web có một đoạn mã JavaScript phía client tự động đọc dữ liệu từ thanh địa chỉ URL thông qua **Source (Nguồn không an toàn):** `window.location.search`.
  * Sau đó, đoạn mã này đưa trực tiếp dữ liệu vừa đọc vào một **Sink (Điểm tiếp nhận nguy hiểm):** `document.write()` mà không thực hiện bất kỳ bước kiểm tra, làm sạch hay mã hóa (encoding) nào.
  * Hậu quả là kẻ tấn công có thể chèn các thẻ HTML và mã JavaScript độc hại vào URL, khi nạn nhân mở liên kết, trình duyệt sẽ tự động thực thi mã JavaScript độc hại dưới danh nghĩa của trang web.

---

### 2. Vì sao nó tồn tại?

Lỗ hổng xuất phát từ việc lập trình viên frontend sử dụng phương thức thao tác DOM không an toàn (`document.write`) kết hợp với việc **nối chuỗi trực tiếp (String Concatenation)** giữa mã HTML và dữ liệu người dùng.

#### Đoạn mã JavaScript gây lỗi trên trang web:
```html
<script>
    function trackSearch(query) {
        document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '">');
    }
    var query = (new URLSearchParams(window.location.search)).get('search');
    if(query) {
        trackSearch(query);
    }
</script>
```

#### Phân tích nguyên nhân gốc rễ (Root Cause):
1. **Source không an toàn:** `(new URLSearchParams(window.location.search)).get('search')` lấy trực tiếp giá trị của tham số `search` từ thanh địa chỉ URL do người dùng kiểm soát.
2. **Sink nguy hiểm:** Hàm `document.write()` nhận một chuỗi văn bản và yêu cầu trình duyệt phân tích cú pháp HTML ngay lập tức trong quá trình tải trang.
3. **Ngữ cảnh xuất hiện (Context):** Input của người dùng rơi vào bên trong giá trị của thuộc tính ảnh: `src="/resources/images/tracker.gif?searchTerms=INPUT">`. 
4. **Thiếu cơ chế xử lý:** Dữ liệu không hề được mã hóa các ký tự điều khiển HTML (như dấu ngoặc kép `"` và dấu ngoặc nhọn `< >`), cho phép kẻ tấn công dễ dàng "đóng sớm" thuộc tính `src` và thẻ `<img>` hiện tại để mở một thẻ HTML mới có khả năng chạy JavaScript.

---

### 3. Cách khai thác

Mục tiêu của bài lab: Tạo ra một payload làm xuất hiện hộp thoại `alert(1)` trên màn hình để giải quyết bài lab.

#### 3.1. Phân tích ngữ cảnh & Xây dựng Payload

Nhìn vào đoạn mã trong sink:
```javascript
document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '">');
```

Để chèn được mã JavaScript, payload cần phải:
1. Đóng thuộc tính `searchTerms="..."` bằng dấu ngoặc kép `"`.
2. Đóng thẻ `<img>` ban đầu bằng dấu `>`.
3. Mở một thẻ HTML mới có khả năng tự động thực thi JavaScript (ở đây dùng thẻ `<svg onload=...>`).

#### 3.2. Payload khai thác hoàn chỉnh:
```html
"><svg onload=alert(1)>
```

#### 🔍 Bảng giải thích chi tiết từng thành phần Payload:

| Thành phần | Ý nghĩa & Cơ chế hoạt động chi tiết |
| :--- | :--- |
| `"` | **Dấu ngoặc kép:** Dùng để đóng giá trị của thuộc tính `src="/resources/images/tracker.gif?searchTerms="` sớm hơn dự định trong chuỗi HTML của `document.write`. |
| `>` | **Dấu đóng thẻ:** Kết thúc hoàn toàn thẻ `<img>` ban đầu, ngăn không cho payload bị kẹt lại bên trong làm một thuộc tính của ảnh. |
| `<svg` | **Thẻ mở SVG:** Bắt đầu một phần tử đồ họa vector (Scalable Vector Graphics) hợp lệ của chuẩn HTML5. Thẻ này được chọn vì nó hỗ trợ thuộc tính sự kiện `onload` ngay cả khi chèn động vào DOM. |
| `onload=` | **Thuộc tính sự kiện (Event Handler):** Chỉ thị cho trình duyệt tự động kích hoạt đoạn mã JavaScript đi kèm ngay sau khi phần tử SVG này được tải và render thành công vào cây DOM (không cần bất kỳ tương tác nào từ phía người dùng như click hay hover). |
| `alert(1)` | **Hàm JavaScript thực thi:** Gọi hộp thoại modal cảnh báo với giá trị `1` ra màn hình — đây là Proof of Concept (PoC) tiêu chuẩn chứng minh mã JavaScript tùy ý đã chạy thành công. |
| `>` | **Dấu đóng thẻ SVG:** Hoàn thiện cú pháp của thẻ `<svg>`. |

*(Lưu ý: Dấu `">` còn sót lại của code gốc phía sau sẽ trở thành chuỗi ký tự text vô hại nằm ngoài thẻ: `...><svg onload=alert(1)>">`)*

---

#### 3.3. Các bước thực hiện khai thác thực tế:

1. **Bước 1:** Mở trang chủ của bài Lab trên trình duyệt.
2. **Bước 2:** Nhập vào ô tìm kiếm (Search Box) chuỗi payload:
   ```text
   "><svg onload=alert(1)>
   ```
   *(Hoặc gắn trực tiếp vào thanh địa chỉ URL: `https://<YOUR-LAB-ID>.web-security-academy.net/?search=%22%3E%3Csvg+onload=alert(1)%3E`)*
3. **Bước 3:** Nhấn nút **Search**.
4. **Bước 4:** Kiểm tra mã nguồn cây DOM (Inspect Elements):
   Trình duyệt nhận chuỗi từ `document.write` và dựng thành cấu trúc DOM:
   ```html
   <img src="/resources/images/tracker.gif?searchTerms=">
   <svg onload="alert(1)"></svg>
   ">
   ```
5. **Kết quả:** Thẻ `<svg>` vừa được render vào DOM lập tức kích hoạt sự kiện `onload`, hộp thoại `alert(1)` nổ ra trên màn hình $\rightarrow$ **Bài lab chuyển sang trạng thái "Solved" thành công!**

---

### 4. Cách phòng chống triệt để

Để loại bỏ hoàn toàn lỗ hổng DOM-based XSS này, cần áp dụng các biện pháp sau:

#### 4.1. Thay thế Sink nguy hiểm bằng API thao tác DOM an toàn (Khuyên dùng)
Tuyệt đối không sử dụng `document.write()` hoặc `element.innerHTML` với dữ liệu lấy từ URL. Thay vào đó, hãy sử dụng các phương thức tạo phần tử và gán thuộc tính thuần túy (`createElement`, `setAttribute`, `src`):

##### Đoạn mã sau khi sửa an toàn:
```javascript
function trackSearchSafe(query) {
    // 1. Tạo đối tượng phần tử Image thông qua DOM API an toàn
    var img = document.createElement('img');
    
    // 2. Gán giá trị thuộc tính qua hàm encodeURIComponent để mã hóa tham số URL
    img.src = '/resources/images/tracker.gif?searchTerms=' + encodeURIComponent(query);
    
    // 3. Đính phần tử vào body
    document.body.appendChild(img);
}

var query = (new URLSearchParams(window.location.search)).get('search');
if (query) {
    trackSearchSafe(query);
}
```

* **Vì sao cách này an toàn?** Khi gán `img.src = ...`, trình duyệt hiểu toàn bộ chuỗi truyền vào chỉ là **một giá trị URL**, không bao giờ phân tích nó thành cú pháp thẻ HTML. Kể cả người dùng có nhập `"><svg onload=alert(1)>`, nó chỉ bị coi là một đường dẫn ảnh bị lỗi, hoàn toàn không thể thoát ra ngoài để sinh thẻ mới.

---

#### 4.2. Mã hóa dữ liệu theo ngữ cảnh (Context-aware Encoding)
Nếu bắt buộc phải in ra HTML, phải mã hóa các ký tự điều khiển HTML trước khi đưa vào:
* `"` đổi thành `&quot;`
* `<` đổi thành `&lt;`
* `>` đổi thành `&gt;`

---

#### 4.3. Thiết lập Content Security Policy (CSP)
Cấu hình HTTP Header CSP từ máy chủ để cấm trình duyệt chạy các đoạn mã JavaScript inline hoặc từ các thuộc tính sự kiện:
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
```
Khi có CSP này, kể cả khi thẻ `<svg onload=alert(1)>` được chèn vào DOM, trình duyệt sẽ chủ động chặn không cho sự kiện `onload` thực thi mã JavaScript.
