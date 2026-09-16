# WH Guardian — 화이트햇 방어 AI

본인 자산(웹/API·이 Windows PC)을 지키는 **방어 전용** 시스템입니다.

하지 않는 것: 익스플로잇, 공격 PoC, 페이로드 재현, 키로거, 클립보드 감시, 타인 시스템 침투.

## 구성

| 구성 요소 | 역할 | 기본 포트 |
|---|---|---|
| `engine/` | 이벤트 수집, 규칙 탐지, 차단, LLM 분류, 패턴 승인 | 8000 |
| `sensors/http_gateway/` | 웹/API 앞단 검사·거부 (데모 앱 포함) | 8080 |
| `sensors/windows_agent/` | 프로세스·연결·파일 변경 센서 | — |
| `dashboard/` | 경보 / 공격면 / 수비 패턴 / 타임라인 | 5173 |
| `patterns/` | YAML 수비 규칙 (승인 시 핫 리로드) | — |

핵심 루프: **센서 → 정규화 이벤트 → 규칙/이상 점수/LLM → 대응 → 경보 → (운영자 승인) 새 패턴**.

## 요구 사항

- Python 3.12+
- Node.js 18+
- (선택) `OPENAI_API_KEY` 또는 `GEMINI_API_KEY` — 없으면 규칙 엔진만 동작

## 실행

프로젝트 루트에서:

```powershell
copy .env.example .env
.\start.ps1
```

브라우저: [http://127.0.0.1:5173](http://127.0.0.1:5173)

보호된 데모 API: [http://127.0.0.1:8080](http://127.0.0.1:8080)

수동 실행:

```powershell
pip install -r engine/requirements.txt -r sensors/http_gateway/requirements.txt -r sensors/windows_agent/requirements.txt
cd dashboard; npm install; cd ..

# 터미널 1
python -m engine.app.main

# 터미널 2
python sensors/http_gateway/main.py

# 터미널 3
python sensors/windows_agent/agent.py

# 터미널 4
cd dashboard; npm run dev
```

## 합성 이벤트로 확인 (공격 재현 아님)

대시보드 상단 버튼 또는:

- 과도한 요청 수 → IP 일시 차단
- 인증 없이 `/admin` 접근 → 요청 거부
- 로그인 실패 반복 → IP 일시 차단
- 임시/다운로드 경로 프로세스, 신규 외부 연결, 민감 파일명 변경 → 경보 (Windows 종료·방화벽은 **승인 후**)

게이트웨이 직접 확인:

```powershell
curl http://127.0.0.1:8080/api/items
curl http://127.0.0.1:8080/admin
```

## 수비 패턴

1. 경보에서 **확인 → 패턴 초안**
2. YAML을 검토한 뒤 **승인 후 핫 리로드**
3. `patterns/approved_*.yaml` 로 저장되며 엔진 재시작 없이 적용

규칙은 `특징 + 임계값 + 대응` 형태입니다. 페이로드를 복제하지 않습니다.

## 환경 변수

`.env.example` 참고. `UPSTREAM_URL`을 설정하면 게이트웨이가 실제 앱으로 프록시합니다.
