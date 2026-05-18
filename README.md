# Claude Pentest Plugin

Đây là repository dùng để quản lý marketplace và các plugin phục vụ kiểm thử an ninh ứng dụng web trong Claude Code. Hiện tại repo tập trung vào plugin `pentest-plugin`, bao gồm agent và các skill hỗ trợ trinh sát, phân tích JavaScript phía client và các tác vụ pentest liên quan.

## Mục đích của repository

Repository này được tổ chức theo hướng:

- Quản lý danh sách plugin thông qua marketplace cục bộ.
- Đóng gói các plugin theo từng thư mục riêng biệt.
- Khai báo agent và skill để Claude Code có thể nạp và sử dụng.
- Lưu các script, tài liệu tham chiếu và cấu hình phục vụ phân tích bảo mật.


## Mô tả chi tiết từng thành phần

### 1. `.claude-plugin/`
Thư mục cấp gốc dùng để khai báo marketplace của repo.

#### `.claude-plugin/marketplace.json`
File mô tả marketplace cục bộ, bao gồm:

- tên marketplace
- thông tin owner
- danh sách plugin có trong repo
- metadata liên quan để Claude Code có thể nhận diện nguồn plugin

Đây là điểm vào chính khi cài plugin từ marketplace của dự án.

### 2. `plugins/`
Thư mục chứa các plugin riêng biệt. Mỗi plugin nên được đóng gói trong một thư mục độc lập để dễ quản lý version, manifest, agent và skill.

---

## Plugin hiện có

### `plugins/pentest-plugin/`

Chức năng chính:

- cung cấp agent phục vụ trinh sát mục tiêu
- cung cấp skill phân tích JavaScript phía client
- hỗ trợ thu thập endpoint, secret, auth flow và tín hiệu bảo mật quan trọng


---

### `plugins/report-plugin/`
Thư mục dành cho plugin báo cáo. (Continue...)

- sinh báo cáo pentest
- chuẩn hóa kết quả scan
- xuất báo cáo theo template


## Luồng hoạt động tổng quát

1. Claude Code đọc marketplace từ `.claude-plugin/marketplace.json`.
2. Marketplace trỏ đến plugin `plugins/pentest-plugin/`.
3. Plugin được định nghĩa bởi `.claude-plugin/plugin.json`.
4. Claude Code nạp các thành phần bên trong plugin như:
   - agent trong `agents/`
   - skill trong `skills/`

