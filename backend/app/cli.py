"""관리 명령 (컨테이너 안에서 실행)

  docker compose exec api python -m app.cli create-user juwon
  docker compose exec api python -m app.cli reset-password juwon
  docker compose exec api python -m app.cli reset-totp juwon      # 휴대폰 분실 시 2단계 인증 초기화
  docker compose exec api python -m app.cli unlock juwon
"""
import getpass
import sys

from sqlalchemy import delete

from .db import Base, SessionLocal, engine
from .models import Session, User
from .security import hash_password, password_problem


def _ask_pw() -> str:
    while True:
        a = getpass.getpass("새 비밀번호: ")
        p = password_problem(a)
        if p:
            print(p)
            continue
        if getpass.getpass("한 번 더: ") != a:
            print("두 번 입력한 값이 다릅니다.")
            continue
        return a


def main() -> None:
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    cmd, name = sys.argv[1], sys.argv[2]
    Base.metadata.create_all(engine)
    db = SessionLocal()
    u = db.query(User).filter(User.username == name).first()
    if cmd == "create-user":
        if u:
            sys.exit("이미 있는 사용자입니다.")
        db.add(User(username=name, pw_hash=hash_password(_ask_pw())))
        db.commit()
        print(f"사용자 '{name}' 생성 완료. 처음 로그인하면 2단계 인증(OTP 앱) 등록 화면이 나옵니다.")
        return
    if not u:
        sys.exit("사용자를 찾을 수 없습니다.")
    if cmd == "reset-password":
        u.pw_hash = hash_password(_ask_pw())
    elif cmd == "reset-totp":
        u.totp_enabled = False
        u.totp_secret_enc = None
        u.last_totp_step = 0
    elif cmd == "unlock":
        u.failed_count = 0
        u.locked_until = None
    else:
        sys.exit(__doc__)
    db.execute(delete(Session).where(Session.user_id == u.id))
    db.commit()
    print("완료. 기존 로그인 세션은 모두 끊었습니다.")


if __name__ == "__main__":
    main()
