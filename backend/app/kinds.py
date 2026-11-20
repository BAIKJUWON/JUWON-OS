"""기록 종류(kind) 정의.

entity: 데이터 소유 구분 (personal / brothers / irobo / bj) — 사업자별 데이터가 섞이지 않도록 서버가 정합니다.
secret: DB에 암호화해서 저장할 필드 (계좌번호 등)
vault:  첨부 파일을 고보안으로 취급할 조건 (열람 전 비밀번호 재확인)
"""

KINDS: dict[str, dict] = {
    # 개인
    "todo": {"entity": "personal"},
    "clip": {"entity": "personal"},
    "note": {"entity": "personal"},
    "exam": {"entity": "personal"},
    "ex_type": {"entity": "personal"},
    "ex_plan": {"entity": "personal"},
    "ex_log": {"entity": "personal"},
    "inbody": {"entity": "personal"},
    "resume_html": {"entity": "personal"},
    "profile": {"entity": "personal"},
    "edu": {"entity": "personal"},
    "job": {"entity": "personal"},
    "cert": {"entity": "personal"},
    "award": {"entity": "personal"},
    "activity": {"entity": "personal"},
    "pfile": {"entity": "personal", "vault": lambda d: d.get("type") in ("인감도장", "서명")},
    "project": {"entity": "personal"},
    "pj_log": {"entity": "personal"},
    "pj_code": {"entity": "personal"},
    "pj_backup": {"entity": "personal"},
    "doc": {"entity": "personal", "vault": lambda d: d.get("level") == "고보안"},
    "fin_account": {"entity": "personal"},
    "fin_flow": {"entity": "personal"},
    "fin_card": {"entity": "personal"},
    "fin_strategy": {"entity": "personal"},
    "link": {"entity": "personal"},
    # 새 메뉴 (2026-11 추가)
    "sv_info": {"entity": "personal"},
    "sv_doc": {"entity": "personal"},
    "term": {"entity": "personal"},
    "cert_goal": {"entity": "personal"},
    "cert_log": {"entity": "personal"},
    "cert_score": {"entity": "personal"},
    "re_note": {"entity": "personal"},
    "re_place": {"entity": "personal"},
    "company": {"entity": "personal"},
    "co_doc": {"entity": "personal"},
    "apply": {"entity": "personal"},
    "apply_step": {"entity": "personal"},
    "apply_file": {"entity": "personal"},
    "apply_qa": {"entity": "personal"},
    "book": {"entity": "personal"},
    # 인감도장관리: 목록 자체가 비밀번호 재확인 뒤에만 보임 (GATED)
    "seal": {"entity": "personal", "vault": lambda d: True},
    "seal_log": {"entity": "personal", "vault": lambda d: True},
    # 브라더스
    # 2026-11 v0.6 추가
    "goal": {"entity": "personal"},
    "retro": {"entity": "personal"},
    "inv_hold": {"entity": "personal"},
    "dividend": {"entity": "personal"},
    "fixed": {"entity": "personal"},
    "loan": {"entity": "personal"},
    "contract": {"entity": "personal"},
    "re_asset": {"entity": "personal"},
    "snapshot": {"entity": "personal"},
    "at_strategy": {"entity": "personal"},
    "at_log": {"entity": "personal"},
    "posting": {"entity": "personal"},
    "ct_prob": {"entity": "personal"},
    "iv_q": {"entity": "personal"},
    "skill": {"entity": "personal"},
    "pj_issue": {"entity": "personal"},
    "job_pf": {"entity": "personal"},
    "br_sale": {"entity": "brothers"},
    "br_partner": {"entity": "brothers"},
    "br_stock": {"entity": "brothers"},
    "br_order": {"entity": "brothers"},
    "br_channel": {"entity": "brothers"},
    "br_contract": {"entity": "brothers"},
    "br_ar": {"entity": "brothers"},
    "br_event": {"entity": "brothers"},
    # 취미·여가
    "h2h_photo": {"entity": "personal"},
    "h2h_event": {"entity": "personal"},
    "h2h_news": {"entity": "personal"},
    "trip": {"entity": "personal"},
    "trip_day": {"entity": "personal"},
    "trip_place": {"entity": "personal"},
    "trip_photo": {"entity": "personal"},
    "dance_show": {"entity": "personal"},
    "dance_video": {"entity": "personal"},
    "dance_song": {"entity": "personal"},
    "dance_member": {"entity": "personal"},
    "dance_retro": {"entity": "personal"},
    "dance_event": {"entity": "personal"},
    "biz_info": {"entity": "brothers"},
    "shipdoc": {"entity": "brothers"},
    "biz_product": {"entity": "brothers"},
    "biz_bank": {"entity": "brothers", "secret": ["acct"]},
    "biz_tax": {"entity": "brothers"},
    "biz_doc": {"entity": "brothers", "vault": lambda d: "인감" in str(d.get("type", ""))},
    "quote": {"entity": "brothers"},
    # 아이로보 위탁판매
    "ir_stock": {"entity": "irobo"},
    "ir_doc": {"entity": "irobo"},
    "ir_bank": {"entity": "irobo", "secret": ["acct"]},
    # 비엔제이
    "bj_card": {"entity": "bj"},
    "bj_doc": {"entity": "bj", "vault": lambda d: d.get("secure") == "고보안"},
    "bj_info": {"entity": "bj"},
    "bj_tax": {"entity": "bj"},
    "bj_sale": {"entity": "bj"},
    "bj_event": {"entity": "bj"},
    # 2026-11 v0.9 추가: 아카이브·강의·회사 업무·아이로보 확장·비엔제이 사업자
    "arc_hs": {"entity": "personal"},      # 고등학교 아카이브
    "arc_univ": {"entity": "personal"},    # 대학교 아카이브
    "arc_study": {"entity": "personal"},   # 공부 아카이브 (고교·대학 공부자료)
    "arc_hw": {"entity": "personal"},      # 과제 아카이브
    "arc_code": {"entity": "personal"},    # 코딩 아카이브 (2017~2022 소스·임시파일)
    "lecture": {"entity": "personal"},     # 내가 만든 강의 자료
    "co_work": {"entity": "personal"},     # 재직 회사 업무 기록
    "ui_pref": {"entity": "personal"},     # 즐겨찾기 등 화면 설정
    "ir_img": {"entity": "irobo"},
    "ir_channel": {"entity": "irobo"},
    "ir_move": {"entity": "irobo"},
    "ir_work": {"entity": "irobo"},
    "ir_tx": {"entity": "irobo"},
    "bj_biz": {"entity": "bj"},
    "bj_buy": {"entity": "bj"},
    # 2026-11 v0.10 사업 ERP (사업자별로 data.org 에 사업 이름이 들어갑니다)
    "org": {"entity": "biz"},          # 사업자 통합관리 (상태: 준비중·운영중·휴업중·폐업·재개예정·법인전환 예정)
    "org_check": {"entity": "biz"},    # 신규사업 준비 체크리스트
    "org_sim": {"entity": "biz"},      # 손익 시뮬레이션
    "sale_ev": {"entity": "biz"},      # 매출 증빙 (카드·현금영수증·기타)
    "bank_tx": {"entity": "biz"},      # 사업용 통장 거래내역 (파일 가져오기)
    "shop_order": {"entity": "biz"},   # 쇼핑몰 주문·배송·정산
    "crm_case": {"entity": "biz"},     # 고객 문의·CS
    "design_asset": {"entity": "biz"}, # 이미지·디자인 자산 (버전)
    "detail_page": {"entity": "biz"},  # 상세페이지 구성 (이미지 순서)
    "site_info": {"entity": "biz"},    # 쇼핑몰·사이트 정보
    "site_work": {"entity": "biz"},    # 사이트 운영일지
    "cms_post": {"entity": "personal"},  # GitHub 웹사이트 글
    "cms_log": {"entity": "personal"},   # GitHub 반영 기록
    # 2026-11 v0.11: 개인 통합수입 · 직원 · 명함 · 발주서
    "income": {"entity": "personal"},     # 개인 수입 (노동·프리랜서·사업)
    "staff": {"entity": "biz"},           # 직원 (여러 사업 소속 가능)
    "staff_org": {"entity": "biz"},       # 직원의 사업별 소속·부서·직급·권한
    "staff_rank": {"entity": "biz"},      # 직급 목록 (이름·표시순서, 관리자가 직접 관리)
    "staff_att": {"entity": "biz"},       # 근태
    "staff_pay": {"entity": "biz"},       # 급여 지급
    "bcard": {"entity": "biz"},           # 명함 템플릿
    "podoc": {"entity": "biz"},           # 발주서
}

# 비밀번호 재확인(최근 10분) 없이는 목록에서 빠지고 추가·수정·삭제도 막히는 종류
GATED = {"seal", "seal_log"}

# 클라이언트가 보내도 data에 저장하지 않는 예약 키
RESERVED = {"id", "kind", "entity", "createdAt", "updatedAt", "fileId", "fileName", "fileSize",
            "fileType", "fileUrl", "isText", "vault", "dedup"}

MAX_DATA_BYTES = 200_000  # 기록 하나의 JSON 크기 상한 (견적서 품목 포함해도 충분)
