# JUWON OS 2.0

개인 기록, 학습, 프로젝트, 자산, 문서와 소규모 사업 기록을 한 곳에서 관리하기 위한 **자기 호스팅 통합관리 웹서비스**입니다.

이 저장소는 개인 데이터·계정·인증서·실제 금융 기록을 포함하지 않는 공개용 Starter Edition입니다. 처음 실행하면 빈 상태에서 시작하며, 본인 데이터는 직접 입력하거나 별도 백업 JSON으로 가져오세요.

> 금융·자동매매·외부 인증 연동은 선택 기능입니다. 실계좌나 인증서를 연결하기 전에 코드와 각 API의 약관을 직접 검토하고, 모의 환경에서 충분히 검증하세요.

## 주요 기능

- 개인: 일정, 할 일, 목표, 운동, 공부 노트, 아카이브, 이력·프로젝트 관리
- 금융: 자산·고정지출·보험·계약 기록, CSV/XLSX 가져오기, 선택적 증권 API 연동
- 사업: 조직별 거래처·상품·매출·매입·문서·직원·일정 관리
- 문서: 파일 업로드, 이미지·PDF·코드 미리보기, 고보안 파일 재인증
- 보안: Argon2id 비밀번호 해시, TOTP 2단계 인증, CSRF, 암호화 저장, 감사 로그
- 운영: Docker Compose, PostgreSQL, NAS 볼륨, 백업 스크립트

## 구조

```text
Browser
  └─ Caddy reverse proxy
       ├─ Next.js + React + TypeScript (frontend)
       └─ FastAPI + SQLAlchemy (backend)
            ├─ PostgreSQL
            └─ local/NAS file volume
```

| 디렉터리 | 역할 |
| --- | --- |
| `frontend/` | Next.js 14, React 18, TypeScript 사용자 화면 |
| `backend/` | FastAPI API, 인증·파일·외부 연동·스케줄러 |
| `seed/` | 개인 정보가 없는 예시 가져오기 JSON |
| `scripts/` | PostgreSQL 백업·복구·업데이트 보조 스크립트 |
| `docker-compose.yml` | 웹·API·DB·프록시 컨테이너 구성 |

## 빠른 시작

### 1. 요구 사항

- Docker Engine + Docker Compose v2
- 최소 2GB RAM 권장
- 외부 공개 시 도메인과 HTTPS 역방향 프록시

### 2. 환경변수 만들기

```bash
cp .env.example .env
openssl rand -base64 36
openssl rand -base64 36
```

`.env`의 `DB_PASSWORD`, `FIELD_KEY`를 각각 서로 다른 무작위 문자열로 바꾸세요. `FIELD_KEY`를 잃으면 암호화된 민감값을 복구할 수 없습니다.

개발 PC에서는 아래처럼 설정하면 됩니다.

```dotenv
DATA_ROOT=./data
COOKIE_SECURE=false
```

HTTPS 배포가 끝나면 반드시 `COOKIE_SECURE=true`로 되돌리세요.

### 3. 실행

```bash
mkdir -p data/files data/db backups
docker compose up -d --build
docker compose ps
docker compose exec api python -m app.cli create-user admin
```

브라우저에서 `http://localhost:8090`으로 접속해 로그인한 뒤 OTP 앱을 등록하세요.

### 4. 로그와 중지

```bash
docker compose logs -f api web
docker compose down
```

## NAS와 외부 접속

Synology Container Manager에서도 같은 `docker compose` 구성을 사용할 수 있습니다. DSM 역방향 프록시가 HTTPS를 처리하고, 이 서비스는 내부 포트(기본 `8090`)만 받도록 구성하세요.

- 인터넷에 DSM 관리 포트(5000/5001)나 앱 포트를 직접 노출하지 마세요.
- 가능한 경우 Tailscale 같은 사설 접속 방식을 우선하세요.
- 외부 공개가 필요하면 443만 역방향 프록시로 전달하고 HTTPS 인증서를 적용하세요.

## 백업과 복구

DB 백업:

```bash
sh scripts/backup.sh "$(pwd)"
```

복구:

```bash
sh scripts/restore.sh backups/db-YYYYMMDD-HHMM.sql.gz "$(pwd)"
```

DB 백업과 `data/files/` 원본 파일은 별도의 암호화 가능한 저장소에도 보관하세요.

## 공개 저장소에 올리면 안 되는 것

- `.env`, 인증서, API 키, OAuth 비밀값, 토큰
- `data/`, `backups/`, DB 덤프, 실제 업로드 문서
- 개인 이력서, 연락처, 계좌·카드·투자 정보
- 운영 로그 전체와 캡처에 포함된 민감정보

커밋 전 다음 명령으로 점검하세요.

```bash
git status --ignored
git grep -n -E "(BEGIN.*KEY|api[_-]?key|secret|password|token)" -- ':!*.example' ':!README.md'
```

## 개발 상태와 한계

- 전체 기능은 개인 운영 목적에서 발전한 코드이므로, 범용 SaaS 수준의 멀티테넌트·권한 분리·마이그레이션 체계는 아직 갖추지 않았습니다.
- 외부 금융 API 응답은 실제 키·계좌 조건에서 추가 검증이 필요할 수 있습니다.
- 실주문은 기본적으로 꺼져 있어야 하며, 사용자가 모든 책임을 집니다.

## 라이선스

[MIT License](LICENSE)를 따릅니다. 자세한 운영 보안 기준은 [SECURITY.md](SECURITY.md)를 확인하세요.
