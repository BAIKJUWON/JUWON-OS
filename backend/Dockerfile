FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv
# PDF 첫 페이지 썸네일용 (pdftoppm)
RUN apt-get update && apt-get install -y --no-install-recommends poppler-utils && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
# pip 다운로드를 빌드 캐시에 남겨 requirements.txt가 바뀌어도 다시 받지 않음
RUN --mount=type=cache,target=/root/.cache/pip pip install -r requirements.txt

COPY app ./app

# 파일 저장 위치 (docker-compose에서 NAS 폴더를 연결)
RUN mkdir -p /data/files && useradd -u 1000 -m appuser && chown -R appuser /data
USER appuser

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
