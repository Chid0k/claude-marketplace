# Claude Pentest Plugin

Đây là repository dùng để quản lý marketplace và các plugin phục vụ kiểm thử an ninh ứng dụng web trong Claude Code. Hiện tại repo tập trung vào plugin `pentest-plugin`, bao gồm agent và các skill hỗ trợ trinh sát, phân tích JavaScript phía client và các tác vụ pentest liên quan.

## Mục đích của repository

Repository này được tổ chức theo hướng:

- Quản lý danh sách plugin thông qua marketplace cục bộ.
- Đóng gói các plugin theo từng thư mục riêng biệt.
- Khai báo agent và skill để Claude Code có thể nạp và sử dụng.
- Lưu các script, tài liệu tham chiếu và cấu hình phục vụ phân tích bảo mật.

## Cấu trúc thư mục

```text
.
├── .claude-plugin/
│   └── marketplace.json
├── plugins/
│   ├── pentest-plugin/
│   │   ├── .claude-plugin/
│   │   │   └── plugin.json
│   │   ├── agents/
│   │   │   └── pentester-recon.md
│   │   └── skills/
│   │       ├── hello/
│   │       │   └── SKILL.md
│   │       └── js-recon/
│   │           ├── references/
│   │           │   └── api-wordlist.txt
│   │           ├── scripts/
│   │           │   ├── beautify_js.py
│   │           │   └── recon_js.py
│   │           └── SKILL.md
│   └── report-plugin/
├── .vscode/
│   ├── settings.json
│   └── .vscode/
│       └── settings.json
└── README.md
```

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
Đây là plugin chính của repository, phục vụ pentest ứng dụng web.

Chức năng chính:

- cung cấp agent phục vụ trinh sát mục tiêu
- cung cấp skill phân tích JavaScript phía client
- hỗ trợ thu thập endpoint, secret, auth flow và tín hiệu bảo mật quan trọng

#### `plugins/pentest-plugin/.claude-plugin/plugin.json`
Manifest của plugin.

File này định nghĩa metadata cơ bản của plugin như:

- tên plugin
- mô tả
- version
- tác giả

Claude Code dùng manifest này để validate và nạp plugin.

#### `plugins/pentest-plugin/agents/`
Chứa các agent dùng riêng cho plugin.

##### `plugins/pentest-plugin/agents/pentester-recon.md`
Đây là sub-agent dùng cho tác vụ trinh sát web/application.

Vai trò chính:

- thu thập thông tin về web server và web application
- hỗ trợ các bước recon ban đầu trước khi đi sâu vào kiểm thử
- đóng vai trò agent chuyên biệt trong workflow pentest

#### `plugins/pentest-plugin/skills/`
Chứa các skill mà plugin cung cấp.

##### `plugins/pentest-plugin/skills/hello/SKILL.md`
Skill đơn giản dùng để chào người dùng.

Mục đích chính:

- làm skill mẫu tối thiểu
- kiểm tra quá trình nạp skill
- minh họa cấu trúc cơ bản của một skill trong plugin

##### `plugins/pentest-plugin/skills/js-recon/`
Skill quan trọng nhất hiện tại trong plugin, tập trung vào phân tích JavaScript phục vụ pentest.

Chức năng của skill này:

- phân tích file JavaScript phía client
- tìm API endpoint
- phát hiện hardcoded secret
- truy vết auth flow phía client
- nhận diện logic mã hóa, GraphQL, admin route và tín hiệu IDOR
- hỗ trợ tạo báo cáo có cấu trúc cho quá trình recon

###### `plugins/pentest-plugin/skills/js-recon/SKILL.md`
File định nghĩa skill `js-recon`.

Nội dung bao gồm:

- mô tả khi nào nên dùng skill
- tool được phép sử dụng
- quy trình phân tích JavaScript
- định dạng đầu ra báo cáo
- hướng dẫn tích hợp với Burp MCP trong workflow phân tích

###### `plugins/pentest-plugin/skills/js-recon/references/api-wordlist.txt`
Danh sách từ khóa/đường dẫn tham chiếu phục vụ suy đoán và đối chiếu API endpoint.

Tác dụng:

- hỗ trợ recon endpoint
- dùng làm wordlist tham khảo khi kiểm tra các route phổ biến

###### `plugins/pentest-plugin/skills/js-recon/scripts/beautify_js.py`
Script hỗ trợ làm đẹp mã JavaScript bị minify hoặc khó đọc.

Tác dụng:

- chuẩn hóa mã trước khi phân tích
- giúp việc dò endpoint, biến, auth flow và secret dễ hơn

###### `plugins/pentest-plugin/skills/js-recon/scripts/recon_js.py`
Script phân tích JavaScript tự động.

Tác dụng chính:

- quét mẫu endpoint
- phát hiện secret và token
- nhận diện dấu hiệu auth/client-side logic
- hỗ trợ tạo đầu ra phục vụ Claude tiếp tục phân tích sâu

---

### `plugins/report-plugin/`
Thư mục dành cho plugin báo cáo.

Ở trạng thái hiện tại, thư mục này chưa có file triển khai bên trong. Có thể xem đây là phần placeholder để mở rộng sau, ví dụ:

- sinh báo cáo pentest
- chuẩn hóa kết quả scan
- xuất báo cáo theo template

### 3. `.vscode/`
Chứa cấu hình dành cho môi trường làm việc trong VS Code.

#### `.vscode/settings.json`
Thiết lập editor/workspace cho dự án.

#### `.vscode/.vscode/settings.json`
Cấu hình phụ hiện có trong repo. Nếu không có mục đích đặc biệt, nên rà soát để tránh trùng lặp hoặc khó hiểu trong workspace settings.

## Luồng hoạt động tổng quát

1. Claude Code đọc marketplace từ `.claude-plugin/marketplace.json`.
2. Marketplace trỏ đến plugin `plugins/pentest-plugin/`.
3. Plugin được định nghĩa bởi `.claude-plugin/plugin.json`.
4. Claude Code nạp các thành phần bên trong plugin như:
   - agent trong `agents/`
   - skill trong `skills/`
5. Khi được gọi, skill `js-recon` sử dụng script và wordlist đi kèm để hỗ trợ phân tích JavaScript.

## Tóm tắt nhanh

- `marketplace.json`: khai báo marketplace của repo.
- `plugin.json`: manifest của plugin.
- `agents/`: chứa sub-agent chuyên dụng.
- `skills/`: chứa các skill mà Claude Code có thể invoke.
- `scripts/`: logic hỗ trợ tự động hóa phân tích.
- `references/`: dữ liệu tham chiếu phục vụ recon.
- `report-plugin/`: vùng mở rộng cho plugin báo cáo trong tương lai.

## Lưu ý sử dụng

Các thành phần trong repo này chỉ nên dùng cho:

- môi trường lab
- nghiên cứu bảo mật
- kiểm thử nội bộ
- hoạt động pentest hợp pháp có ủy quyền

Không nên sử dụng cho các hệ thống ngoài phạm vi được phép kiểm thử.
