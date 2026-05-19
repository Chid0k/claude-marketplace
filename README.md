<p align="center">
  <img src="https://img.shields.io/badge/Recon--Plugin-v1.2.2-blue?style=for-the-badge&logo=github" alt="Recon Plugin v1.2.3">
  <img src="https://img.shields.io/badge/Vuln--Detect--Plugin-v1.0.0-red?style=for-the-badge&logo=github" alt="Vuln Detect Plugin v1.2.2">
  <img src="https://img.shields.io/badge/Python-3.10%2B-green?style=for-the-badge&logo=python" alt="Python Version">
</p>

# Claude Pentest Skills Suite 🛡️🤖

Một bộ công cụ mạnh mẽ được thiết kế dành riêng cho **Claude AI**, biến mô hình ngôn ngữ thành một trợ lý Penetration Testin thực thụ.
---

## Tổng quan dự án

Dự án này cung cấp các endpoint và công cụ tinh chỉnh để Claude có thể tương tác, phân tích dữ liệu tĩnh và động từ các mục tiêu, giảm thiểu thời gian đọc hiểu mã nguồn và hỗ trợ pentester ra quyết định nhanh chóng.

---
## Chi tiết các Plugin

- **_[1.2.3] recon-plugin:_** skill for infomation gathering
    - client-side-assessment: HTML/JS analysis, browser storage assessment, detect hidden endpoint/param/function
    - js-recon: JS analysis, explanation auth flow, encryption analysis, 


- **_[1.2.2] vuln-detect-plugin:_** skill for vulnerabilities assesment / pentest
    - sqli-detect (testing ...)
    - nosqli-detect (testing ...)
    - gen-report (testing ...)


### Thêm marketplace
```bash
claude plugin marketplace add Chid0k/claude-marketplace
```

