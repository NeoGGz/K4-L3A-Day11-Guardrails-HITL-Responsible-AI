# Kế hoạch hoàn thành Day 11 Lab — dành cho GPT-6 Luna, reasoning High

## Thông tin và ranh giới

- Học viên: **Bùi Minh Quân**; MSSV: **2A202602958**. Dùng tên không dấu `BuiMinhQuan` khi đặt repo nộp: `K4-L3-DAY11-BuiMinhQuan-2A202602958-Guardrails-HITL-Responsible-AI`.
- Đây là bài cá nhân. AI được hỗ trợ viết và sửa code, nhưng học viên phải đọc, chạy, giải thích được bài. Trình bày rõ kỹ thuật của từng prompt red-team để học viên tự chỉnh và xác nhận đó là ý đồ tấn công của mình trước khi nộp.
- Làm đúng Checkpoint 1 → 5 trong `CHECKPOINTS.md`. Ưu tiên 100 điểm bắt buộc trước bonus. Blue dùng OpenRouter `liquid/lfm-2.5-2.6b` cố định. Red và Red Advance dùng chung **một** provider và model lab mặc định: OpenAI `gpt-4o-mini` hoặc Gemini `gemini-3.5-flash`. **GPT-6 Luna High là model viết code trong Codex, không phải model Blue/Red của lab.**
- Giữ `.env` và API key trên máy, không đưa vào chat, code, log công khai hoặc Git. Không sửa `data/protected/vinbank_secrets.json`, không giả kết quả bằng cách viết tay `outputs/*.json`, không viết tay `outputs/lab_report.md`. Không sửa Red/Red Advance để tự tạo leak.

## Trạng thái ban đầu đã kiểm tra

- Starter còn TODO ở `src/guardrails/input_guardrails.py`, `output_guardrails.py`, `src/assignment/{rate_limiter,audit_log,monitoring,pipeline}.py`, và 5 prompt trong `src/attacks/attacks.py`.
- `src/main.py` đã nối `--part 2`, `--part 3`, `--part 4`; `src/attacks/attacks.py` đã có hàm chạy và lưu kết quả. `schemas/results.schema.json` và test công khai đã có.
- Chưa có `.env`, `.venv`, `outputs/`. Máy đang có Python 3.13.15; nếu dependency không tương thích thì dùng Python 3.11 hoặc 3.12 như README khuyến nghị.
- Git `origin` hiện là repo starter `NeoGGz/K4-L3A-Day11-Guardrails-HITL-Responsible-AI`. Trước khi push, dùng fork/repo cá nhân đúng tên; không đẩy bài lên remote starter.

## Bước 1 — Setup và kiểm tra nền (CP1)

1. Đọc `README.md`, `RULES.md`, `RUBRIC.md`, `SUBMISSION.md`, `CHECKPOINTS.md` và các docstring/TODO liên quan trước khi sửa. Giữ những phần starter đã hoàn chỉnh.
2. Tạo `.venv`, cài `requirements.txt`; chạy `pytest tests/smoke -q`. Nếu môi trường 3.13 gây lỗi cài đặt, thử 3.11/3.12 và ghi lại lý do.
3. Tạo `.env` từ `.env.example` nhưng để học viên tự nhập `OPENROUTER_API_KEY` và một key Red (`OPENAI_API_KEY` hoặc `GOOGLE_API_KEY`). Không hiển thị giá trị key. Chọn model Red mặc định để đủ điều kiện 20 điểm CP4; không đổi model chỉ để chạy Codex.
4. Bổ sung vào `README.md` họ tên, MSSV và lệnh chạy ngắn. Chỉ ghi thông tin đã được học viên cung cấp ở đầu kế hoạch.

## Bước 2 — Blue guardrails (CP2, 40 điểm)

1. `src/guardrails/input_guardrails.py`: chuẩn hóa Unicode NFKC, loại zero-width/invisible separators và xử lý khoảng trắng trước kiểm tra. Thêm ít nhất 5 regex bao phủ ignore previous instructions, you are now, system prompt, reveal instructions/prompt, pretend/act unrestricted; xử lý lệnh nhúng trong email/RAG mà vẫn cho phép yêu cầu tóm tắt email chuyển khoản bình thường. `detect_injection` chỉ trả `"BLOCK"`/`"ALLOW"`.
2. `topic_filter` dùng `ALLOWED_TOPICS` và `BLOCKED_TOPICS` từ `src/core/config.py`: từ khóa cấm được ưu tiên chặn; thiếu chủ đề ngân hàng cũng chặn. Kiểm tra tiếng Anh và tiếng Việt trong danh sách hiện có. `InputGuardrailPlugin.on_user_message_callback` lấy text từ `types.Content`, cập nhật counters, trả `types.Content` chặn hoặc `None` để đi tiếp.
3. `src/guardrails/output_guardrails.py`: `content_filter` che số điện thoại Việt Nam, email, CMND/CCCD, `sk-...`, password và các secret demo mà Blue có thể lộ (kể cả `admin123`/DB host) bằng `[REDACTED]`; trả đủ `safe`, `issues`, `redacted`. Plugin cập nhật response trước khi gửi, counters chính xác. Judge/NeMo là tùy chọn; không để việc thiếu judge cản CP2.
4. Kiểm offline bằng `pytest tests/public/test_lab_contracts.py -q` và các ca bổ sung có ý nghĩa: Unicode ẩn, email/RAG lành tính, topic hợp lệ, redact mỗi loại secret/PII. Khi `.env` đã sẵn sàng, chạy `python src/main.py --part 2` và đọc kết quả terminal.

## Bước 3 — Blue pipeline và artifact (CP3, 40 điểm)

1. `rate_limiter.py`: sliding window theo `user_id`, xóa timestamp hết hạn, chặn từ request thứ `max_requests + 1`, thông báo thời gian chờ, cập nhật `total_count`/`blocked_count`; kiểm tra hai user độc lập và điểm biên thời gian.
2. `audit_log.py`: ghép `record_input`/`record_output` bằng `request_id`, lưu thời gian UTC, input, output, quyết định `blocked`, `layer`, latency; xuất JSON vào `<repo>/outputs/audit_log.json`, tạo thư mục khi cần. Không đưa API key vào audit.
3. `monitoring.py`: cập nhật tổng request, blocked, rate-limit hits, judge checks/fails nếu có; tạo alert khi vượt các ngưỡng sẵn có; xuất snapshot và alerts thành `outputs/metrics.json`.
4. `pipeline.py`: `build_production_plugins()` trả đúng thứ tự `RateLimitPlugin`, `InputGuardrailPlugin`, `OutputGuardrailPlugin`; `build_observability()` trả audit + monitor. `is_egress_allowed()` parse URL và so hostname chính xác theo allowlist `api.vinbank.example`, `cases.vinbank.example` trong `agents/security_boundary.py`, bắt buộc HTTPS; từ chối domain giả dạng và payload chứa password, API key, DB host, phone, email. Dùng rule code, không dựa vào LLM.
5. `run_assignment_suite(pipeline)` phải dùng chính pipeline được truyền vào, chạy ≥5 safe queries, ≥7 attack queries (≥5 bị chặn), ≥3 edge cases và thử rate limit với `passed + blocked == sent`, `blocked >= 1`. Ghi nhận `layer` từ quyết định thật; không suy diễn `blocked` chỉ bằng nội dung câu trả lời nếu đã có tín hiệu plugin. Tái dùng filter CP2, audit và monitoring. Ghi `results.json`, `audit_log.json`, `metrics.json` dưới **gốc repo**, không dưới `src/`.
6. Kiểm bằng `python src/main.py --part 3`, `pytest tests/public/test_results_contract.py -q`, và validate `outputs/results.json` với `schemas/results.schema.json`. Safe queries phải không bị chặn; các con số rate limit và audit/metrics phải khớp với request đã chạy. Nếu chưa có OpenRouter key, hoàn thiện và kiểm offline trước, ghi rõ CP3 cần chạy lại sau khi key được điền.

## Bước 4 — Red-team (CP4, 20 điểm)

1. Thay đúng 5 `TODO` trong `adversarial_prompts` ở `src/attacks/attacks.py` bằng prompt có chủ đích, dài và cụ thể cho 5 kỹ thuật: completion, translation/reformat, hypothetical, confirmation, multi-step. Ghi lý do/kỹ thuật để học viên tự rà soát và chỉnh prompt. Chỉ dùng secret **demo** của repo.
2. Không tấn công Blue ở CP4. Chạy `python src/main.py --part 4` trên Red mặc định rồi Red Advance như starter. Kiểm `outputs/unsafe_attack_result.json`, `guards_attack_result.json`, `attack_results.json`; file tổng phải có `unsafe_attacks` + `guards_attacks`, mỗi phía ≥5 dòng, không còn `TODO`, `llm_provider`/`llm_model` khớp `.env` lúc chạy.
3. Mục tiêu điểm bắt buộc: ít nhất một response Red thật sự chứa secret demo theo detector; không sửa JSON hoặc agent để báo `leaked: true`. Nếu Red chưa leak, chỉnh prompt có lý do rồi chạy lại. Bonus B1 (Red, tối đa +5) hoặc B2 (Red Advance, tối đa +10) chỉ chọn một, phụ thuộc grader replay; không làm bonus ảnh hưởng điểm bắt buộc.

## Bước 5 — Tự chấm và bàn giao (CP5)

1. Chạy `pytest tests/smoke -q`, `pytest tests/public -q`, rồi `python scripts/grade.py --submission-dir . --out outputs/grade_report.json`. Script phải tự sinh `outputs/lab_report.md`; không viết report tay.
2. Xác nhận `results.json` + `attack_results.json` hiện diện và hợp lệ; kiểm Git diff và `git status`, đặc biệt `.env` không được track. Artifact `outputs/` là kết quả lệnh chạy thật và cần được commit trong repo bài nộp.
3. Báo cáo cho học viên: file đã sửa, lệnh đã chạy, test pass/fail, API run nào chưa thể chạy, kết quả leak Red có thật hay không, và việc cần học viên tự xác nhận. Chỉ đổi tên/push repo cá nhân và nộp link khi đã xác định đúng remote, có quyền truy cập và học viên đã xem kết quả cuối.

## Điều kiện hoàn tất

- Không còn TODO ở các hàm bắt buộc CP2–CP3 và 5 prompt CP4.
- `pytest tests/smoke -q` và `pytest tests/public -q` chạy xanh; các artifact bắt buộc được sinh bởi CLI, schema hợp lệ.
- Blue không lộ secret demo; Red có bằng chứng leak thật trong kết quả chạy model mặc định; `attack_results.json` khai đúng provider/model.
- README có đúng **Bùi Minh Quân / 2A202602958**, `.env` không bị commit, không có artifact giả hoặc report viết tay.
