# Mini SOAR Playbook Engine

경보 수신 → 플레이북 매칭 → 자동 대응(차단/알림/티켓)을 수행하는 경량 SOAR 서버입니다.

## 아키텍처

```
┌─────────────────────────────────────────────────────────────────────┐
│  Kali (192.168.100.3)                                               │
│       │ 공격 트래픽                                                  │
│       ▼                                                             │
│  fwips (192.168.100.6)  ◄── Snort IPS (/var/log/snort/alert)      │
│       │                                                             │
│       │  POST /api/alerts (rsyslog 또는 스크립트)                    │
│       ▼                                                             │
│  SOAR VM (192.168.100.35)                                           │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Flask API (app.py)                                          │   │
│  │    └─ snort_parser.py   ← alert 파싱                         │   │
│  │    └─ playbook_engine.py ← 조건 매칭                         │   │
│  │         └─ actions/                                          │   │
│  │              ├─ block.py   → SSH → fwips iptables FORWARD   │   │
│  │              ├─ slack.py   → Slack Webhook POST              │   │
│  │              └─ notion.py  → Notion API POST                 │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## 디렉터리 구조

```
mini-soar/
├── app.py               # Flask REST API 서버
├── snort_parser.py      # Snort alert 파서
├── playbook_engine.py   # 플레이북 매칭 & 실행 엔진
├── actions/
│   ├── __init__.py      # 액션 디스패처
│   ├── block.py         # SSH → fwips iptables 차단
│   ├── slack.py         # Slack Webhook 알림
│   └── notion.py        # Notion 인시던트 티켓 생성
├── playbooks/
│   ├── shellshock.yml   # Shellshock 대응 플레이북
│   └── port_scan.yml
├── logs/                # soar.log 생성 위치
├── incidents/           # incidents.json 생성 위치
├── requirements.txt
├── .env.example
└── README.md
```

## 설치

```bash
cd /home/soaradmin/mini-soar

# 가상환경 생성
python3 -m venv venv
source venv/bin/activate

# 의존성 설치
pip install -r requirements.txt

# 환경 변수 설정
cp .env.example .env
nano .env   # 실제 값으로 수정
```

## 환경 변수 (.env)

| 변수 | 설명 | 예시 |
|------|------|------|
| `FLASK_HOST` | 바인딩 주소 | `0.0.0.0` |
| `FLASK_PORT` | 포트 | `5000` |
| `FWIPS_HOST` | fwips IP | `192.168.100.6` |
| `SSH_KEY_PATH` | SSH 개인키 경로 | `~/.ssh/id_rsa` |
| `SLACK_WEBHOOK_URL` | Slack Incoming Webhook URL | `your-slack-webhook-url-here` |
| `NOTION_API_KEY` | Notion Integration 토큰 | `secret_xxx` |
| `NOTION_DATABASE_ID` | 인시던트 DB ID | `32자리 hex` |

## 실행

```bash
source venv/bin/activate
python app.py
```

서버가 `0.0.0.0:5000`에서 시작됩니다.

### 서비스로 등록 (systemd)

```ini
# /etc/systemd/system/mini-soar.service
[Unit]
Description=Mini SOAR Playbook Engine
After=network.target

[Service]
User=soaradmin
WorkingDirectory=/home/soaradmin/mini-soar
ExecStart=/home/soaradmin/mini-soar/venv/bin/python app.py
Restart=on-failure
EnvironmentFile=/home/soaradmin/mini-soar/.env

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mini-soar
```

## fwips 연동 설정

fwips의 rsyslog 또는 커스텀 스크립트에서 Snort alert가 발생할 때 SOAR로 POST합니다.

### 방법 1 — 커스텀 스크립트 (권장)

`/usr/local/bin/snort_to_soar.sh` (fwips에 배치):

```bash
#!/bin/bash
SOAR_URL="http://192.168.100.35:5000/api/alerts"
tail -F /var/log/snort/alert | while IFS= read -r line; do
    [[ "$line" == \[\*\*\]* ]] || continue
    curl -s -X POST "$SOAR_URL" \
         -H "Content-Type: text/plain" \
         --data "$line" &
done
```

### 방법 2 — rsyslog omhttp 모듈

```
# /etc/rsyslog.d/50-soar.conf (fwips)
module(load="omhttp")
if $programname == 'snort' then {
    action(type="omhttp"
           server="192.168.100.35"
           serverport="5000"
           restpath="api/alerts"
           template="RSYSLOG_PlainMsg")
}
```

## REST API 엔드포인트

| Method | Path | 설명 |
|--------|------|------|
| `POST` | `/api/alerts` | Snort alert 수신 (text/plain 또는 JSON `{"raw": "..."}`) |
| `GET`  | `/api/status` | SOAR 상태, 플레이북 목록 |
| `GET`  | `/api/incidents` | 인시던트 목록 (최근 100건) |
| `GET`  | `/api/incidents/<id>` | 단건 조회 |
| `GET`  | `/api/playbooks` | 로드된 플레이북 목록 |
| `POST` | `/api/playbooks/reload` | 플레이북 핫 리로드 |

### 테스트 예시

```bash
# Shellshock alert 테스트
curl -s -X POST http://192.168.100.35:5000/api/alerts \
  -H "Content-Type: text/plain" \
  --data '[**] [1:2014:1] SHELLSHOCK HTTP request [**] [Classification: Web App Attack] [Priority: 1] {TCP} 192.168.100.3:54321 -> 10.10.11.10:80'

# 상태 확인
curl -s http://192.168.100.35:5000/api/status | python3 -m json.tool

# 인시던트 목록
curl -s http://192.168.100.35:5000/api/incidents | python3 -m json.tool
```

## 플레이북 작성 가이드

`playbooks/*.yml` 파일을 추가하면 서버 재시작 없이 `/api/playbooks/reload`로 반영됩니다.

```yaml
name: My Playbook          # 필수
description: 설명          # 선택
enabled: true              # false이면 로드 스킵

conditions:                # 모두 AND 조건
  signature_regex: "패턴"  # 정규식 (IGNORECASE)
  signature_contains: "문자열"
  severity: "high"         # high / medium / low
  severity_in:             # 여러 severity 허용
    - high
    - medium
  priority_lte: 2          # Snort Priority ≤ N (1=high)
  protocol: "TCP"
  attacker_ip: "1.2.3.4"
  target_ip: "10.10.11.10"
  classification_contains: "Web App"

actions:
  - type: block_ip         # SSH → fwips iptables DROP

  - type: slack_notify
    message: |
      공격 탐지: {attacker_ip} → {target_ip}
      서명: {signature} / 심각도: {severity}

  - type: notion_ticket
    title: "[INCIDENT] {signature} from {attacker_ip}"
    priority: "{severity}"  # high / medium / low

  - type: log              # SOAR 로그에만 기록
    message: "탐지: {signature}"
```

### 템플릿 변수

| 변수 | 내용 |
|------|------|
| `{attacker_ip}` | 공격자 IP |
| `{attacker_port}` | 공격자 포트 |
| `{target_ip}` | 대상 IP |
| `{target_port}` | 대상 포트 |
| `{signature}` | Snort 서명 이름 |
| `{sig_id}` | gid:sid:rev |
| `{severity}` | high / medium / low |
| `{priority}` | Snort Priority 숫자 |
| `{protocol}` | TCP / UDP / ICMP |
| `{classification}` | Snort 분류 |
| `{timestamp}` | Snort 타임스탬프 |

## Notion DB 설정

Notion에서 인시던트 데이터베이스를 생성하고 아래 컬럼을 추가하세요:

| 컬럼명 | 타입 | 옵션 |
|--------|------|------|
| Name | Title | — |
| Status | Select | Open, In Progress, Resolved |
| Priority | Select | High, Medium, Low |
| Attacker IP | Rich Text | — |
| Target IP | Rich Text | — |
| Signature | Rich Text | — |
| Date | Date | — |

Integration을 DB에 공유(Share)한 뒤 `.env`에 `NOTION_DATABASE_ID`를 설정합니다.
