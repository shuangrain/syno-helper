# 1. 建構階段：利用 uv 快取安裝相依套件 (Python 3.11，與 Debian 12 Distroless 保持一致)
FROM ghcr.io/astral-sh/uv:python3.11-bookworm-slim AS builder

WORKDIR /app

# 預先編譯 bytecode，加快執行啟動速度
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

# 先複製依賴設定檔，利用 Docker Layer 快取
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --python 3.11 --frozen --no-install-project --no-dev

# 複製專案原始碼並安裝專案
COPY . .
RUN uv sync --python 3.11 --frozen --no-dev

# 2. 執行階段：使用 Google Distroless Python3 (Debian 12)
FROM gcr.io/distroless/python3-debian12

WORKDIR /app

# 複製已編譯好的 site-packages 與原始碼
COPY --from=builder /app/.venv/lib/python3.11/site-packages /site-packages
COPY --from=builder /app/src /app/src

ENV PYTHONPATH="/site-packages:/app/src"

ENTRYPOINT ["/usr/bin/python3", "-m", "syno_helper.main"]