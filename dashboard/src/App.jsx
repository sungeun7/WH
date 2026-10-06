import { useEffect, useMemo, useRef, useState } from "react";
import { api, connectWs } from "./api";

const NAV = [
  ["alerts", "경보"],
  ["surface", "공격면"],
  ["blocks", "차단"],
  ["patterns", "수비 규칙"],
  ["timeline", "기록"],
  ["settings", "설정"],
];

const TITLES = {
  alerts: "경보",
  surface: "공격면",
  blocks: "차단",
  patterns: "수비 규칙",
  timeline: "기록",
  settings: "설정",
};

const FALLBACK_AI = [
  { id: "auto", name: "자동 (키 있는 모델)", ready: true, selected: true, active: false },
  { id: "openai", name: "OpenAI", ready: false, selected: false, active: false },
  { id: "gemini", name: "Gemini", ready: false, selected: false, active: false },
  { id: "none", name: "규칙만 (AI 끄기)", ready: true, selected: false, active: false },
];

const SYNTH = [
  ["http_burst", "요청 폭주"],
  ["unauth_admin", "미인증 /admin"],
  ["auth_fail_burst", "로그인 실패 폭주"],
  ["process_from_temp", "임시 폴더 프로세스"],
  ["new_outbound", "신규 외부 연결"],
  ["file_change", "민감 파일 변경"],
];

const SEV = { critical: "치명", high: "높음", medium: "중간", low: "낮음" };
const SURFACE_KIND = {
  http_path: "HTTP 경로",
  outbound: "외부 연결",
  process: "프로세스",
  listen_port: "수신 포트",
  file: "파일",
};
const BLOCK_KIND = { ip: "IP", path: "경로", port: "포트" };
const ACTION_KIND = {
  kill_process: "프로세스 종료",
  firewall_block: "방화벽 차단",
  deny_ip: "IP 차단",
};
const REC = {
  deny_ip: "IP 차단 권장",
  deny_request: "요청 거부 권장",
  alert: "검토 권장",
  kill_process: "프로세스 종료 권장",
  firewall_block: "방화벽 차단 권장",
};
const DONE = {
  resolve: "경보를 처리했습니다.",
  "resolve-all": "열린 경보를 모두 처리했습니다.",
  confirm: "수비 규칙 초안을 만들었습니다. 수비 규칙에서 승인하세요.",
  block: "차단을 걸었습니다.",
  exec: "이 PC에서 조치를 실행했습니다.",
  mitigate: "해당 공격면을 막도록 올렸습니다.",
  approve: "규칙을 승인하고 바로 적용했습니다.",
  reject: "초안을 거절했습니다.",
  settings: "설정을 저장했습니다.",
  ai: "사용할 AI를 바꿨습니다.",
  "timeline-del": "기록을 지웠습니다.",
  "timeline-clear": "기록을 모두 지웠습니다.",
  unblock: "차단을 해제했습니다.",
  cancel: "대기 조치를 취소했습니다.",
};

function severityClass(value) {
  const v = (value || "low").toLowerCase();
  if (v === "critical" || v === "high") return "sev high";
  if (v === "medium") return "sev medium";
  return "sev low";
}

function when(ts) {
  if (!ts) return "";
  const n = typeof ts === "number" ? ts * 1000 : Date.parse(ts);
  if (Number.isNaN(n)) return "";
  return new Date(n).toLocaleString("ko-KR");
}

function aiName(id) {
  if (id === "openai") return "OpenAI";
  if (id === "gemini") return "Gemini";
  if (id === "none") return "규칙만";
  if (id === "auto") return "자동";
  return (id || "규칙만").toUpperCase();
}

function actionLabel(item) {
  const payload = item.payload || {};
  const kind = ACTION_KIND[item.kind] || item.kind;
  if (item.kind === "kill_process") {
    const name = payload.name || payload.process_name || "프로세스";
    return `${kind}: ${name}${payload.pid ? ` (PID ${payload.pid})` : ""}`;
  }
  if (item.kind === "firewall_block") {
    const dest = payload.dest_ip || payload.addr || "";
    const port = payload.dest_port || payload.listen_port;
    return `${kind}: ${dest}${port ? `:${port}` : ""}`.trim();
  }
  if (item.kind === "deny_ip") return `${kind}: ${payload.value || ""}`;
  return kind;
}

function actionHint(item) {
  if (item.kind === "kill_process") return "이 PC에서 해당 프로세스를 강제 종료합니다.";
  if (item.kind === "firewall_block") return "이 PC 방화벽에 차단 규칙을 넣습니다. 관리자 권한이 필요할 수 있습니다.";
  if (item.kind === "deny_ip") return "해당 IP의 HTTP 요청을 거부합니다.";
  return "";
}

function blockReason(reason) {
  const text = String(reason || "");
  if (text.startsWith("alert:")) return "경보를 처리하면서 차단했습니다.";
  if (text.startsWith("surface:")) return "공격면에서 막아 두었습니다.";
  if (text === "http_rate_limit") return "요청이 너무 많아 잠시 막았습니다.";
  if (text === "deny_ip") return "IP 차단 규칙";
  return text;
}

function surfaceAction(item) {
  if (item.kind === "http_path") return "이 경로 차단";
  if (item.kind === "outbound") return "연결 차단 대기";
  if (item.kind === "process") return "종료 승인 대기";
  if (item.kind === "listen_port") return "포트 차단 대기";
  return "차단";
}

export default function App() {
  const [tab, setTab] = useState("alerts");
  const [stats, setStats] = useState({});
  const [live, setLive] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [surface, setSurface] = useState([]);
  const [patterns, setPatterns] = useState([]);
  const [drafts, setDrafts] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [blocks, setBlocks] = useState([]);
  const [actions, setActions] = useState([]);
  const [settings, setSettings] = useState(null);
  const [busy, setBusy] = useState("");
  const [toast, setToast] = useState(null);
  const [aiOpen, setAiOpen] = useState(false);
  const [surfaceFilter, setSurfaceFilter] = useState("high");
  const [testOpen, setTestOpen] = useState(false);
  const [confirmAll, setConfirmAll] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);
  const settingsSaveRef = useRef(null);

  const refresh = async () => {
    const results = await Promise.allSettled([
      api.stats(),
      api.alerts(),
      api.surface(),
      api.patterns(),
      api.drafts(),
      api.timeline(),
      api.blocks(),
      api.actions(),
      api.settings(),
    ]);
    const value = (i, fallback) =>
      results[i].status === "fulfilled" ? results[i].value : fallback;
    setStats(value(0, {}));
    setAlerts(value(1, []));
    setSurface(value(2, []));
    setPatterns(value(3, []));
    setDrafts(value(4, []));
    setTimeline(value(5, []));
    setBlocks(value(6, []));
    setActions(value(7, []));
    setSettings(value(8, settings));
    if (results[0].status === "rejected") {
      setLive(false);
      setToast({ type: "err", text: "엔진에 연결하지 못했습니다. 8000 포트를 확인하세요." });
    }
  };

  useEffect(() => {
    refresh().catch(() => {
      setLive(false);
      setToast({ type: "err", text: "엔진에 연결하지 못했습니다. 8000 포트를 확인하세요." });
    });
    let timer = null;
    const ws = connectWs(
      () => {
        setLive(true);
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => refresh().catch(() => {}), 400);
      },
      () => setLive(true),
      () => setLive(false)
    );
    const poll = setInterval(() => refresh().catch(() => {}), 8000);
    return () => {
      clearInterval(poll);
      if (timer) clearTimeout(timer);
      ws.close();
    };
  }, []);

  useEffect(() => {
    if (!toast || toast.type === "err") return undefined;
    const timer = setTimeout(() => setToast(null), 4000);
    return () => clearTimeout(timer);
  }, [toast]);

  const run = async (label, fn) => {
    setBusy(label);
    setToast(null);
    try {
      await fn();
      await refresh();
      if (DONE[label]) setToast({ type: "ok", text: DONE[label] });
      else if (SYNTH.some(([kind]) => kind === label)) {
        setToast({ type: "ok", text: "테스트 이벤트를 넣었습니다. 경보를 확인하세요." });
      }
    } catch (err) {
      setToast({ type: "err", text: String(err.message || err) });
    } finally {
      setBusy("");
    }
  };

  const openAlerts = useMemo(
    () => alerts.filter((a) => a.status === "open"),
    [alerts]
  );
  const pendingActions = useMemo(
    () => actions.filter((x) => x.status === "pending"),
    [actions]
  );
  const nextAlert = openAlerts[0];
  const aiProviders = stats.ai_providers?.length ? stats.ai_providers : FALLBACK_AI;
  const mitigate = (settings?.resolve_action || "mitigate") === "mitigate";

  const goTab = (id, extra) => {
    setAiOpen(false);
    setConfirmAll(false);
    setConfirmClear(false);
    extra?.();
    setTab(id);
  };

  useEffect(() => {
    if (!aiOpen) return undefined;
    const close = (event) => {
      if (!event.target.closest?.(".kpis li.ai-open")) setAiOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [aiOpen]);

  const resolveNext = () => {
    if (!nextAlert) return;
    setAlerts((prev) => prev.filter((a) => a.id !== nextAlert.id));
    return run("resolve", () => api.resolveAlert(nextAlert.id));
  };

  const resolveAll = () => {
    setConfirmAll(false);
    setAlerts([]);
    return run("resolve-all", () => api.resolveAllAlerts());
  };

  return (
    <div className="shell">
      <aside>
        <div className="brand">
          <div className="mark">WH</div>
          <div>
            <strong>Guardian</strong>
            <em>내 자산 방어</em>
          </div>
        </div>
        <div className={`conn ${live ? "on" : "off"}`}>{live ? "엔진 연결됨" : "엔진 끊김"}</div>
        <nav>
          {NAV.map(([id, label]) => (
            <button
              key={id}
              className={tab === id ? "active" : ""}
              onClick={() => {
                if (id === "surface") setSurfaceFilter("high");
                goTab(id);
              }}
            >
              {label}
              {id === "alerts" && openAlerts.length > 0 ? <span className="badge">{openAlerts.length}</span> : null}
              {id === "blocks" && pendingActions.length > 0 ? (
                <span className="badge warn">{pendingActions.length}</span>
              ) : null}
              {id === "patterns" && drafts.length > 0 ? <span className="badge">{drafts.length}</span> : null}
            </button>
          ))}
        </nav>
        <div className="aside-foot">
          <p>본인 PC·웹만 지킵니다.</p>
          <p>공격 재현·익스플로잇 없음</p>
        </div>
      </aside>
      <main>
        {tab === "alerts" ? (
          <div className="action-bar">
            <button className="primary lg" disabled={!nextAlert || !!busy} onClick={resolveNext}>
              {busy === "resolve" ? "처리 중…" : "다음 경보 처리"}
            </button>
            {confirmAll ? (
              <span className="confirm-all">
                <span>열린 경보 {openAlerts.length}건을 모두 처리할까요?</span>
                <button className="primary" disabled={!!busy} onClick={resolveAll}>
                  확인
                </button>
                <button type="button" onClick={() => setConfirmAll(false)}>
                  취소
                </button>
              </span>
            ) : (
              <button className="lg" disabled={openAlerts.length === 0 || !!busy} onClick={() => setConfirmAll(true)}>
                모두 처리
              </button>
            )}
            <span className="meta action-explain">
              {nextAlert
                ? `${openAlerts.length}건 · 다음: ${nextAlert.title}`
                : "처리할 경보가 없습니다"}
              {" · "}
              {mitigate ? "처리 시 원인 차단" : "지금은 목록에서만 제거"}
            </span>
          </div>
        ) : tab === "settings" ? (
          <div className="action-bar">
            <button className="primary lg" disabled={!!busy} onClick={() => settingsSaveRef.current?.()}>
              {busy === "settings" ? "저장 중…" : "설정 저장"}
            </button>
            <span className="meta">바꾼 내용을 저장해야 적용됩니다.</span>
          </div>
        ) : tab === "timeline" ? (
          <div className="action-bar">
            {confirmClear ? (
              <span className="confirm-all">
                <span>기록 {timeline.length}건을 모두 삭제할까요? 되돌릴 수 없습니다.</span>
                <button
                  className="danger"
                  disabled={!!busy}
                  onClick={() => {
                    setConfirmClear(false);
                    run("timeline-clear", () => api.clearTimeline());
                  }}
                >
                  삭제
                </button>
                <button type="button" onClick={() => setConfirmClear(false)}>
                  취소
                </button>
              </span>
            ) : (
              <>
                <button
                  className="danger lg"
                  disabled={timeline.length === 0 || !!busy}
                  onClick={() => setConfirmClear(true)}
                >
                  기록 모두 삭제
                </button>
                <span className="meta">{timeline.length}건 보관 중</span>
              </>
            )}
          </div>
        ) : (
          <div className="action-bar slim">
            <span className="meta">
              {openAlerts.length}건 대기
              {pendingActions.length > 0 ? ` · 승인 대기 ${pendingActions.length}건` : ""}
            </span>
            {openAlerts.length > 0 && tab !== "alerts" ? (
              <button type="button" onClick={() => goTab("alerts")}>
                경보 보기
              </button>
            ) : null}
            {pendingActions.length > 0 && tab !== "blocks" ? (
              <button type="button" onClick={() => goTab("blocks")}>
                승인 대기 보기
              </button>
            ) : null}
          </div>
        )}

        <header>
          <div>
            <h1>{TITLES[tab] || ""}</h1>
            <p>
              {tab === "alerts" && "의심 행위를 확인하고, 처리하면 목록에서 사라집니다."}
              {tab === "surface" && "우리 쪽에서 노출된 경로·포트·연결입니다. 막으려면 차단을 누르세요."}
              {tab === "blocks" && "이미 막힌 것과, 이 PC에서 한 번 더 승인이 필요한 조치입니다."}
              {tab === "patterns" && "초안을 승인하면 같은 행위를 다음부터 자동으로 막습니다."}
              {tab === "timeline" && "처리·차단·설정 변경 기록입니다."}
              {tab === "settings" && "AI와 처리 방식을 고릅니다. 상단 AI 버튼으로도 모델을 바꿀 수 있습니다."}
            </p>
          </div>
          <ul className="kpis">
            <li className={tab === "alerts" ? "current" : ""}>
              <button type="button" onClick={() => goTab("alerts")}>
                <b>{stats.open_alerts ?? openAlerts.length}</b>
                <span>열린 경보</span>
              </button>
            </li>
            <li className={tab === "surface" && surfaceFilter === "high" ? "current" : ""}>
              <button type="button" onClick={() => goTab("surface", () => setSurfaceFilter("high"))}>
                <b>{stats.high_surface ?? 0}</b>
                <span>고위험 공격면</span>
              </button>
            </li>
            <li className={tab === "blocks" ? "current" : ""}>
              <button type="button" onClick={() => goTab("blocks")}>
                <b>{stats.active_blocks ?? blocks.length}</b>
                <span>활성 차단</span>
              </button>
            </li>
            <li className={`${aiOpen ? "ai-open" : ""} ${tab === "settings" ? "current" : ""}`.trim()}>
              <button type="button" onClick={() => setAiOpen((open) => !open)}>
                <b>{aiName(stats.llm)}</b>
                <span>AI</span>
              </button>
              {aiOpen ? (
                <div className="ai-menu" onMouseDown={(e) => e.stopPropagation()}>
                  <p>사용할 AI를 고르세요</p>
                  {aiProviders.map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      className={p.selected || p.active ? "active" : ""}
                      onClick={() => {
                        if (!p.ready && p.id !== "none") {
                          goTab("settings");
                          return;
                        }
                        setAiOpen(false);
                        run("ai", () => api.saveSettings({ llm_provider: p.id }));
                      }}
                    >
                      <strong>{p.name}</strong>
                      <em>{p.ready ? (p.active ? "사용 중" : "선택") : "키 필요 · 설정"}</em>
                    </button>
                  ))}
                </div>
              ) : null}
            </li>
          </ul>
        </header>

        {toast ? <div className={`notice ${toast.type}`}>{toast.text}</div> : null}

        {tab === "alerts" ? (
          <Alerts
            alerts={openAlerts}
            pending={pendingActions.length}
            settings={settings}
            busy={busy}
            onGoBlocks={() => goTab("blocks")}
            onGoPatterns={() => goTab("patterns")}
            onConfirm={(id) =>
              run("confirm", async () => {
                await api.confirmAlert(id);
                setAlerts((prev) => prev.filter((a) => a.id !== id));
              })
            }
            onResolve={(id) => {
              setAlerts((prev) => prev.filter((a) => a.id !== id));
              return run("resolve", () => api.resolveAlert(id));
            }}
            onBlock={(id) => {
              setAlerts((prev) => prev.filter((a) => a.id !== id));
              return run("block", () => api.blockAlert(id));
            }}
          />
        ) : null}
        {tab === "surface" ? (
          <Surface
            items={surface}
            filter={surfaceFilter}
            onFilter={setSurfaceFilter}
            onMitigate={(id) => run("mitigate", () => api.mitigate(id))}
          />
        ) : null}
        {tab === "blocks" ? (
          <Blocks
            blocks={blocks}
            actions={pendingActions}
            busy={busy}
            onExecute={(id) => run("exec", () => api.executeAction(id))}
            onUnblock={(id) => run("unblock", () => api.removeBlock(id))}
            onCancel={(id) => run("cancel", () => api.cancelAction(id))}
          />
        ) : null}
        {tab === "patterns" ? (
          <Patterns
            patterns={patterns}
            drafts={drafts}
            onApprove={(id) => run("approve", () => api.approveDraft(id))}
            onReject={(id) => run("reject", () => api.rejectDraft(id))}
          />
        ) : null}
        {tab === "timeline" ? (
          <Timeline
            items={timeline}
            busy={busy}
            onDelete={(id) => run("timeline-del", () => api.deleteTimeline(id))}
          />
        ) : null}
        {tab === "settings" ? (
          <Settings
            settings={settings}
            busy={busy}
            saveRef={settingsSaveRef}
            onSave={(body) => run("settings", async () => setSettings(await api.saveSettings(body)))}
          />
        ) : null}

        {tab === "alerts" ? (
          <details className="test-events" open={testOpen} onToggle={(e) => setTestOpen(e.currentTarget.open)}>
            <summary>테스트용 합성 이벤트</summary>
            <p>실제 공격이 아닙니다. 화면이 어떻게 바뀌는지 볼 때만 쓰세요.</p>
            <div className="synth">
              {SYNTH.map(([kind, label]) => (
                <button
                  key={kind}
                  type="button"
                  disabled={!!busy}
                  onClick={() => {
                    goTab("alerts");
                    run(kind, () => api.synthetic(kind, { count: kind.includes("burst") ? 12 : 1 }));
                  }}
                >
                  {busy === kind ? "전송 중…" : label}
                </button>
              ))}
            </div>
          </details>
        ) : null}
      </main>
    </div>
  );
}

function Alerts({ alerts, pending, settings, busy, onGoBlocks, onGoPatterns, onConfirm, onResolve, onBlock }) {
  const mitigate = (settings?.resolve_action || "mitigate") === "mitigate";
  const ordered = [...alerts].sort((a, b) => {
    const rank = { critical: 0, high: 1, medium: 2, low: 3 };
    return (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9);
  });
  return (
    <div className="stack">
      {pending > 0 ? (
        <button type="button" className="pending-banner" onClick={onGoBlocks}>
          Windows 조치 {pending}건이 실행 승인을 기다립니다. 차단 화면으로
        </button>
      ) : null}
      <article>
        <div className="row">
          <h2>열린 경보</h2>
          <span className="meta">{ordered.length}건</span>
        </div>
        <p className="hint">
          {mitigate
            ? "처리: HTTP는 바로 막고, 프로세스 종료·방화벽은 설정대로 승인하거나 실행합니다."
            : "지금은 목록에서만 지웁니다. 원인을 없애려면 설정에서 ‘원인 차단/종료’를 켜세요."}
        </p>
        <div className="list">
          {ordered.length === 0 ? (
            <Empty
              text="지금은 열린 경보가 없습니다. 게이트웨이와 Windows 센서가 켜져 있으면 자동으로 나타납니다."
              extra="동작을 보려면 아래 테스트 이벤트를 펼치세요."
            />
          ) : null}
          {ordered.map((a) => (
            <div className={`card ${a.severity === "high" || a.severity === "critical" ? "hot" : ""}`} key={a.id}>
              <div className="row">
                <span className={severityClass(a.severity)}>{SEV[a.severity] || a.severity}</span>
                <strong>{a.title}</strong>
              </div>
              <p>{a.rationale}</p>
              <p className="meta">
                {REC[a.recommended_action] || a.recommended_action} · {when(a.created_at)}
              </p>
              <div className="row actions">
                <button className="primary" disabled={!!busy} onClick={() => onResolve(a.id)}>
                  처리
                </button>
                <button disabled={!!busy} onClick={() => onConfirm(a.id)}>
                  규칙 초안
                </button>
                {!mitigate ? (
                  <button className="danger" disabled={!!busy} onClick={() => onBlock(a.id)}>
                    차단하고 닫기
                  </button>
                ) : null}
              </div>
              <p className="tiny">
                규칙 초안은 같은 행위를 다음부터 자동으로 막기 위한 초안만 만들고 경보를 닫습니다.
                {mitigate ? "" : " 차단하고 닫기는 목록 제거와 함께 원인을 막습니다."}
              </p>
            </div>
          ))}
        </div>
        {ordered.length > 0 ? (
          <p className="hint linkish">
            초안을 승인하려면{" "}
            <button type="button" className="text-link" onClick={onGoPatterns}>
              수비 규칙
            </button>
            으로 이동하세요.
          </p>
        ) : null}
      </article>
    </div>
  );
}

function Surface({ items, filter = "high", onFilter, onMitigate }) {
  const [showAll, setShowAll] = useState(false);
  const counts = {
    high: items.filter((item) => item.risk === "high").length,
    outbound: items.filter((item) => item.kind === "outbound").length,
    listen_port: items.filter((item) => item.kind === "listen_port").length,
  };
  const visible = items.filter((item) => {
    if (filter === "high") return item.risk === "high";
    if (filter === "outbound" || filter === "listen_port" || filter === "http_path") {
      return item.kind === filter;
    }
    return true;
  });
  const shown = showAll ? visible : visible.slice(0, 40);
  return (
    <article>
      <div className="row">
        <h2>우리 쪽 노출</h2>
        {[
          ["high", `고위험 ${counts.high}`],
          ["http_path", "경로"],
          ["listen_port", `포트 ${counts.listen_port}`],
          ["outbound", `연결 ${counts.outbound}`],
          ["all", `전체 ${items.length}`],
        ].map(([id, label]) => (
          <button
            key={id}
            className={filter === id ? "primary" : "ghost"}
            onClick={() => {
              setShowAll(false);
              onFilter && onFilter(id);
            }}
          >
            {label}
          </button>
        ))}
      </div>
      <p className="hint">
        {filter === "high"
          ? "당장 볼 고위험만 보여 줍니다. 연결·포트가 많으면 전체에서 찾으세요."
          : "막으면 HTTP 경로는 바로 차단되고, 포트·연결·프로세스는 차단 화면에서 한 번 더 승인합니다."}
      </p>
      <table>
        <thead>
          <tr>
            <th>위험</th>
            <th>종류</th>
            <th>항목</th>
            <th>상태</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {visible.length === 0 ? (
            <tr>
              <td colSpan={5}>
                {filter === "high"
                  ? "고위험 공격면이 없습니다. 포트·연결·전체에서 나머지를 볼 수 있습니다."
                  : "아직 관측된 항목이 없습니다. HTTP 게이트웨이 또는 Windows 센서를 실행하세요."}
              </td>
            </tr>
          ) : null}
          {shown.map((item) => (
            <tr key={item.id}>
              <td>
                <span className={severityClass(item.risk)}>{SEV[item.risk] || item.risk}</span>
              </td>
              <td>{SURFACE_KIND[item.kind] || item.kind}</td>
              <td>
                <strong>{item.title}</strong>
                <div className="meta">{item.detail}</div>
              </td>
              <td>{item.status === "open" ? "관찰 중" : "조치함"}</td>
              <td>
                {item.status === "open" ? (
                  <button type="button" onClick={() => onMitigate(item.id)}>
                    {surfaceAction(item)}
                  </button>
                ) : (
                  "완료"
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {visible.length > shown.length ? (
        <p className="hint">
          {shown.length} / {visible.length}건{" "}
          <button type="button" className="text-link" onClick={() => setShowAll(true)}>
            나머지 더 보기
          </button>
        </p>
      ) : null}
    </article>
  );
}

function Blocks({ blocks, actions, busy, onExecute, onUnblock, onCancel }) {
  return (
    <div className="grid two">
      <article>
        <h2>지금 막힌 것</h2>
        {blocks.length === 0 ? <Empty text="활성 차단이 없습니다. 경보를 처리하면 HTTP IP·경로가 여기에 쌓입니다." /> : null}
        {blocks.map((b) => (
          <div className="card slim" key={b.id}>
            <strong>
              {BLOCK_KIND[b.kind] || b.kind}: {b.value}
            </strong>
            <p className="meta">{blockReason(b.reason)}</p>
            <button type="button" disabled={!!busy} onClick={() => onUnblock(b.id)}>
              차단 해제
            </button>
          </div>
        ))}
      </article>
      <article>
        <h2>이 PC에서 승인 필요</h2>
        {actions.length === 0 ? (
          <Empty text="프로세스 종료나 방화벽 변경 대기가 없습니다. 설정에서 ‘처리 후 승인’이면 여기에 나타납니다." />
        ) : null}
        {actions.map((x) => (
          <div className="card slim hot" key={x.id}>
            <strong>{actionLabel(x)}</strong>
            <p className="meta">{actionHint(x)}</p>
            <div className="row">
              <button className="danger" disabled={!!busy} onClick={() => onExecute(x.id)}>
                이 PC에서 실행
              </button>
              <button type="button" disabled={!!busy} onClick={() => onCancel(x.id)}>
                취소
              </button>
            </div>
          </div>
        ))}
      </article>
    </div>
  );
}

function Patterns({ patterns, drafts, onApprove, onReject }) {
  return (
    <div className="grid two">
      <article>
        <div className="row">
          <h2>승인 대기 초안</h2>
          <span className="meta">{drafts.length}건</span>
        </div>
        {drafts.length === 0 ? <Empty text="경보에서 ‘규칙 초안’을 누르면 여기에 검토할 규칙이 생깁니다." /> : null}
        {drafts.map((d) => (
          <div className="card" key={d.id}>
            <div className="row">
              <strong>{d.name}</strong>
              <em>{d.origin === "llm" ? "AI 초안" : "규칙 초안"}</em>
            </div>
            <details>
              <summary>규칙 내용 보기</summary>
              <pre>{d.yaml_text}</pre>
            </details>
            <div className="row">
              <button className="primary" onClick={() => onApprove(d.id)}>
                승인하고 적용
              </button>
              <button className="ghost" onClick={() => onReject(d.id)}>
                거절
              </button>
            </div>
          </div>
        ))}
      </article>
      <article>
        <h2>이미 켜진 규칙</h2>
        {patterns.length === 0 ? <Empty text="적용된 규칙이 없습니다." /> : null}
        {patterns.map((p) => (
          <div className="card" key={p.id}>
            <div className="row">
              <strong>{p.name}</strong>
              <em>{p.enabled ? "켜짐" : "꺼짐"}</em>
            </div>
            <p>{p.description}</p>
            <p className="meta">
              {SEV[p.severity] || p.severity} · {p.auto_respond ? "자동 대응" : "경보만"}
            </p>
          </div>
        ))}
      </article>
    </div>
  );
}

function Timeline({ items, busy, onDelete }) {
  const KIND = {
    alert: "경보",
    block: "차단",
    action: "조치",
    pattern: "규칙",
    settings: "설정",
    surface: "공격면",
    event: "이벤트",
  };
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("all");
  const visible = items.filter((item) => {
    if (kind !== "all" && item.kind !== kind) return false;
    if (!q.trim()) return true;
    const hay = `${item.summary || ""} ${item.kind || ""}`.toLowerCase();
    return hay.includes(q.trim().toLowerCase());
  });
  const kinds = ["all", ...Array.from(new Set(items.map((item) => item.kind).filter(Boolean)))];
  return (
    <article>
      <div className="row">
        <h2>최근 활동</h2>
        <span className="meta">{visible.length}건</span>
        <input
          className="search"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="기록 검색"
        />
      </div>
      <div className="row chips">
        {kinds.map((id) => (
          <button key={id} type="button" className={kind === id ? "primary" : "ghost"} onClick={() => setKind(id)}>
            {id === "all" ? "전체" : KIND[id] || id}
          </button>
        ))}
      </div>
      <div className="list">
        {visible.length === 0 ? <Empty text={items.length === 0 ? "아직 기록이 없습니다." : "검색과 맞는 기록이 없습니다."} /> : null}
        {visible.map((item) => (
          <div className="card slim" key={item.id}>
            <div className="row">
              <span className="pill">{KIND[item.kind] || item.kind}</span>
              <strong>{item.summary}</strong>
              <em>{when(item.ts || item.timestamp)}</em>
              <button type="button" className="ghost" disabled={!!busy} onClick={() => onDelete(item.id)}>
                삭제
              </button>
            </div>
          </div>
        ))}
      </div>
    </article>
  );
}

function Settings({ settings, busy, onSave, saveRef }) {
  const [form, setForm] = useState(
    settings || {
      resolve_action: "mitigate",
      http_block_on_resolve: true,
      windows_process: "confirm",
      windows_firewall: "confirm",
      http_auto_respond: true,
      llm_provider: "auto",
      openai_api_key: "",
      gemini_api_key: "",
    }
  );

  useEffect(() => {
    if (!settings) return;
    setForm({
      resolve_action: settings.resolve_action ?? "mitigate",
      http_block_on_resolve: settings.http_block_on_resolve ?? true,
      windows_process: settings.windows_process ?? "confirm",
      windows_firewall: settings.windows_firewall ?? "confirm",
      http_auto_respond: settings.http_auto_respond ?? true,
      llm_provider: settings.llm_provider ?? "auto",
      openai_api_key: "",
      gemini_api_key: "",
    });
  }, [settings]);

  const set = (key, value) => setForm((prev) => ({ ...prev, [key]: value }));

  const save = () => {
    const body = { ...form };
    if (!body.openai_api_key) delete body.openai_api_key;
    if (!body.gemini_api_key) delete body.gemini_api_key;
    onSave(body);
  };

  useEffect(() => {
    if (!saveRef) return undefined;
    saveRef.current = save;
    return () => {
      saveRef.current = null;
    };
  });

  return (
    <article className="settings">
      <h2>AI</h2>
      <p className="hint">키가 있는 모델을 고르면 경보 설명과 규칙 초안을 도와줍니다. 없어도 규칙은 동작합니다.</p>
      <fieldset>
        <legend>사용할 모델</legend>
        {(settings?.ai_providers || FALLBACK_AI).map((p) => (
          <label key={p.id}>
            <input
              type="radio"
              name="llm_provider"
              checked={(form.llm_provider || "auto") === p.id}
              onChange={() => set("llm_provider", p.id)}
            />
            {p.name}
            {p.ready ? "" : " — 키 없음"}
          </label>
        ))}
      </fieldset>
      <fieldset>
        <legend>API 키</legend>
        <label className="stack-label">
          OpenAI
          <input
            type="password"
            autoComplete="off"
            placeholder={settings?.openai_key_set ? "저장됨 · 바꾸려면 새 키 입력" : "여기에 키 붙여넣기"}
            value={form.openai_api_key || ""}
            onChange={(e) => set("openai_api_key", e.target.value)}
          />
        </label>
        <label className="stack-label">
          Gemini
          <input
            type="password"
            autoComplete="off"
            placeholder={settings?.gemini_key_set ? "저장됨 · 바꾸려면 새 키 입력" : "여기에 키 붙여넣기"}
            value={form.gemini_api_key || ""}
            onChange={(e) => set("gemini_api_key", e.target.value)}
          />
        </label>
      </fieldset>

      <h2>처리 버튼을 누르면</h2>
      <fieldset>
        <legend>경보 처리</legend>
        <label>
          <input
            type="radio"
            name="resolve_action"
            checked={form.resolve_action === "mitigate"}
            onChange={() => set("resolve_action", "mitigate")}
          />
          원인까지 막고 목록에서 제거 (권장)
        </label>
        <label>
          <input
            type="radio"
            name="resolve_action"
            checked={form.resolve_action === "ack"}
            onChange={() => set("resolve_action", "ack")}
          />
          오탐 확인용 — 목록에서만 제거
        </label>
      </fieldset>

      <fieldset>
        <legend>웹/API</legend>
        <label>
          <input
            type="checkbox"
            checked={!!form.http_block_on_resolve}
            onChange={(e) => set("http_block_on_resolve", e.target.checked)}
          />
          처리 시 해당 IP·경로 차단
        </label>
        <label>
          <input
            type="checkbox"
            checked={!!form.http_auto_respond}
            onChange={(e) => set("http_auto_respond", e.target.checked)}
          />
          탐지되면 요청을 바로 거부 (403/429)
        </label>
      </fieldset>

      <fieldset>
        <legend>이 PC 프로세스</legend>
        {[
          ["off", "종료하지 않음"],
          ["confirm", "처리 후 차단 화면에서 한 번 더 승인 (권장)"],
          ["execute", "처리와 동시에 종료 (오탐 주의)"],
        ].map(([id, label]) => (
          <label key={id}>
            <input
              type="radio"
              name="windows_process"
              checked={form.windows_process === id}
              onChange={() => set("windows_process", id)}
            />
            {label}
          </label>
        ))}
      </fieldset>

      <fieldset>
        <legend>이 PC 방화벽</legend>
        {[
          ["off", "바꾸지 않음"],
          ["confirm", "처리 후 차단 화면에서 한 번 더 승인 (권장)"],
          ["execute", "처리와 동시에 적용 (관리자 권한 필요할 수 있음)"],
        ].map(([id, label]) => (
          <label key={id}>
            <input
              type="radio"
              name="windows_firewall"
              checked={form.windows_firewall === id}
              onChange={() => set("windows_firewall", id)}
            />
            {label}
          </label>
        ))}
      </fieldset>

      <p className="meta">모두 처리는 한꺼번에 여러 프로그램을 죽이지 않도록, 종료·방화벽은 항상 승인 대기로 넣습니다.</p>
    </article>
  );
}

function Empty({ text, extra }) {
  return (
    <div className="empty-box">
      <p className="empty">{text}</p>
      {extra ? <p className="meta">{extra}</p> : null}
    </div>
  );
}
