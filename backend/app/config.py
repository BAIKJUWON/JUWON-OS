"""환경변수 설정. 값은 docker-compose의 .env에서 들어옵니다."""
import os


def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://juwon:juwon@db:5432/juwon_os")
# 민감 필드(계좌번호·TOTP 비밀값) 암호화 키. 아무 긴 무작위 문자열이면 되고, 내부에서 Fernet 키로 변환합니다.
FIELD_KEY = os.getenv("FIELD_KEY", "")
FILES_DIR = os.getenv("FILES_DIR", "/data/files")
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "50"))
COOKIE_SECURE = _bool("COOKIE_SECURE", True)          # HTTPS로만 접속하면 true 유지
SESSION_HOURS = int(os.getenv("SESSION_HOURS", "12"))  # 로그인 유지 최대 시간
IDLE_MINUTES = int(os.getenv("IDLE_MINUTES", "120"))   # 이 시간 동안 아무 요청이 없으면 로그아웃
REMEMBER_DAYS = int(os.getenv("REMEMBER_DAYS", "30"))  # "로그인 유지" 체크 시 세션 유지 일수 (유휴 로그아웃 없음)
TRUST_DAYS = int(os.getenv("TRUST_DAYS", "90"))  # "이 기기 신뢰" 시 OTP를 다시 묻지 않는 일수
REAUTH_MINUTES = int(os.getenv("REAUTH_MINUTES", "10"))  # 고보안 파일 열람 전 재인증 유효 시간
LOGIN_MAX_FAIL = int(os.getenv("LOGIN_MAX_FAIL", "5"))
LOGIN_LOCK_MINUTES = int(os.getenv("LOGIN_LOCK_MINUTES", "15"))
TOTP_ISSUER = os.getenv("TOTP_ISSUER", "JUWON OS")

# ---- 한국투자증권 Open API (KIS Developers) ----
KIS_ENV = os.getenv("KIS_ENV", "real").strip().lower()           # real(실전, 기본) / paper(모의투자)
KIS_APP_KEY = os.getenv("KIS_APP_KEY", "").strip()
KIS_APP_SECRET = os.getenv("KIS_APP_SECRET", "").strip()
KIS_ACCOUNT = os.getenv("KIS_ACCOUNT", "").replace("-", "").strip()  # 계좌번호 앞 8자리
KIS_ACCOUNT_PROD = os.getenv("KIS_ACCOUNT_PROD", "01").strip()     # 계좌상품코드 (뒤 2자리)

# 두 번째 한국투자증권 계좌 (미니스탁을 다른 계좌번호로 쓰는 경우 등). 앱키는 계좌마다 따로 발급됩니다.
KIS2_NAME = os.getenv("KIS2_NAME", "한국투자증권 2").strip()
KIS2_ENV = os.getenv("KIS2_ENV", "real").strip().lower()
KIS2_APP_KEY = os.getenv("KIS2_APP_KEY", "").strip()
KIS2_APP_SECRET = os.getenv("KIS2_APP_SECRET", "").strip()
KIS2_ACCOUNT = os.getenv("KIS2_ACCOUNT", "").replace("-", "").strip()
KIS2_ACCOUNT_PROD = os.getenv("KIS2_ACCOUNT_PROD", "01").strip()

# ---- 키움증권 REST API (openapi.kiwoom.com) — 잔고 조회 ----
KIWOOM_ENV = os.getenv("KIWOOM_ENV", "real").strip().lower()       # real / mock
KIWOOM_APP_KEY = os.getenv("KIWOOM_APP_KEY", "").strip()
KIWOOM_SECRET = os.getenv("KIWOOM_SECRET", "").strip()

# ---- 자동매매 · 자동 불러오기 ----
# 실제 주문은 이 값이 true이고 화면에서 '실주문'으로 켰을 때만 나갑니다. 기본은 주문 없이 기록만(모의 실행).
AUTOTRADE_LIVE = _bool("AUTOTRADE_LIVE", False)
AUTO_SYNC_MINUTES = int(os.getenv("AUTO_SYNC_MINUTES", "180"))     # 증권·은행 자동 불러오기 주기(분). 0이면 끔
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()              # 선택: 없어도 공개 저장소는 조회됨(시간당 60회)
# ---- GitHub 웹사이트 CMS (선택: OAuth 앱으로 연결. 없으면 화면에서 토큰을 붙여 넣어 연결) ----
GITHUB_OAUTH_ID = os.getenv("GITHUB_OAUTH_ID", "").strip()
GITHUB_OAUTH_SECRET = os.getenv("GITHUB_OAUTH_SECRET", "").strip()
PUBLIC_URL = os.getenv("PUBLIC_URL", "").strip().rstrip("/")     # 예: https://your-domain.example (OAuth 콜백 주소)

# ---- CODEF (인증서 기반 은행·카드 조회) ----
CODEF_MODE = os.getenv("CODEF_MODE", "sandbox").strip().lower()    # sandbox / demo / product
CODEF_CLIENT_ID = os.getenv("CODEF_CLIENT_ID", "").strip()
CODEF_CLIENT_SECRET = os.getenv("CODEF_CLIENT_SECRET", "").strip()
CODEF_PUBLIC_KEY = os.getenv("CODEF_PUBLIC_KEY", "").strip()

if len(FIELD_KEY) < 24:
    raise RuntimeError("FIELD_KEY 환경변수가 비어 있거나 너무 짧습니다 (24자 이상). .env를 확인하세요.")
