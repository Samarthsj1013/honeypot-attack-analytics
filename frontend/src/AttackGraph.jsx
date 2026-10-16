import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import axios from "axios";

import { API } from "./api";
const TYPES = ["source_ip", "session", "command", "alert", "technique"];
const COLORS = {
  source_ip: "#38bdf8", session: "#a78bfa", command: "#34d399",
  alert: "#fb7185", technique: "#fbbf24",
};
const LABELS = {
  source_ip: "Source IP", session: "Session", command: "Observed command",
  alert: "Alert", technique: "ATT&CK technique",
};

export default function AttackGraph({ filters, onSelectAttacker }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [enabledTypes, setEnabledTypes] = useState(TYPES);
  const [focusIp, setFocusIp] = useState("");
  const [focusSession, setFocusSession] = useState("");
  const [selected, setSelected] = useState(null);
  const [selectedAlertId, setSelectedAlertId] = useState("");
  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState("");
  const [zoom, setZoom] = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const [canvasWidth, setCanvasWidth] = useState(1000);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const drag = useRef(null);
  const canvasWrapRef = useRef(null);
  const expandButtonRef = useRef(null);
  const closeFullscreenButtonRef = useRef(null);

  useEffect(() => {
    if (!isFullscreen) return undefined;
    const previousBodyOverflow = document.body.style.overflow;
    const previousRootOverflow = document.documentElement.style.overflow;
    document.body.style.overflow = "hidden";
    document.documentElement.style.overflow = "hidden";
    const focusFrame = window.requestAnimationFrame(() => closeFullscreenButtonRef.current?.focus());
    function handleFullscreenKeyDown(event) {
      if (event.key === "Escape") {
        event.preventDefault();
        setIsFullscreen(false);
        window.requestAnimationFrame(() => expandButtonRef.current?.focus());
      }
    }
    document.addEventListener("keydown", handleFullscreenKeyDown);
    return () => {
      window.cancelAnimationFrame(focusFrame);
      document.body.style.overflow = previousBodyOverflow;
      document.documentElement.style.overflow = previousRootOverflow;
      document.removeEventListener("keydown", handleFullscreenKeyDown);
    };
  }, [isFullscreen]);

  function exitFullscreen() {
    setIsFullscreen(false);
    window.requestAnimationFrame(() => expandButtonRef.current?.focus());
  }

  useEffect(() => {
    const canvas = canvasWrapRef.current;
    if (!canvas) return undefined;
    const updateWidth = () => setCanvasWidth(Math.max(1000, Math.floor(canvas.clientWidth)));
    updateWidth();
    if (typeof ResizeObserver !== "undefined") {
      const observer = new ResizeObserver(updateWidth);
      observer.observe(canvas);
      return () => observer.disconnect();
    }
    window.addEventListener("resize", updateWidth);
    return () => window.removeEventListener("resize", updateWidth);
  }, [isFullscreen]);

  useEffect(() => {
    let active = true;
    async function loadGraph() {
      setLoading(true);
      setError("");
      try {
        const params = { ...filters, limit: 120 };
        if (!params.start) delete params.start;
        if (!params.end) delete params.end;
        if (!params.behavior) delete params.behavior;
        if (focusIp.trim()) params.source_ip = focusIp.trim();
        if (focusSession.trim()) params.session_id = focusSession.trim();
        const response = await axios.get(`${API}/api/attack-graph`, { params });
        if (!Array.isArray(response.data?.nodes) || !Array.isArray(response.data?.edges)) {
          throw new Error("Unexpected graph response");
        }
        if (active) {
          setData(response.data);
          setSelected(null);
          setDetail(null);
        }
      } catch (err) {
        if (active) {
          setData(null);
          setError(err.response?.data?.detail || "Unable to load the attack relationship graph.");
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    loadGraph();
    return () => { active = false; };
  }, [filters, focusIp, focusSession]);

  const visibleNodes = useMemo(() => {
    const query = search.trim().toLowerCase();
    return (data?.nodes || []).filter((node) => enabledTypes.includes(node.type) &&
      (!query || `${node.label} ${JSON.stringify(node.metadata || {})}`.toLowerCase().includes(query)));
  }, [data, enabledTypes, search]);
  const graphNodes = useMemo(() => {
    const alertGroups = new Map();
    const sessionsByAlert = new Map();
    for (const edge of data?.edges || []) {
      if (edge.relationship !== "alert_evidence" || !edge.target?.startsWith("alert:") || !edge.source?.startsWith("session:")) continue;
      const alertId = edge.target.slice("alert:".length);
      if (!sessionsByAlert.has(alertId)) sessionsByAlert.set(alertId, new Set());
      sessionsByAlert.get(alertId).add(edge.source.slice("session:".length));
    }
    const nodes = [];
    const aliases = new Map();
    for (const node of visibleNodes) {
      if (node.type !== "alert") {
        nodes.push(node);
        aliases.set(node.id, node.id);
        continue;
      }
      const key = String(node.label || "Alert").trim().toLocaleLowerCase();
      if (!alertGroups.has(key)) alertGroups.set(key, []);
      alertGroups.get(key).push(node);
    }
    for (const [titleKey, members] of alertGroups) {
      const sortedMembers = [...members].sort((left, right) =>
        String(left.metadata?.source_ip || "").localeCompare(String(right.metadata?.source_ip || "")) ||
        String(left.metadata?.first_seen || "").localeCompare(String(right.metadata?.first_seen || "")) ||
        String(left.metadata?.alert_id || "").localeCompare(String(right.metadata?.alert_id || "")));
      const id = `alert-group:${encodeURIComponent(titleKey)}`;
      const node = {
        id,
        type: "alert",
        label: sortedMembers[0]?.label || "Alert",
        metadata: {
          alert_count: sortedMembers.length,
          alerts: sortedMembers.map((member) => ({
            node_id: member.id,
            label: member.label,
            ...(member.metadata || {}),
            session_ids: [...(sessionsByAlert.get(member.metadata?.alert_id) || [])].sort(),
          })),
        },
      };
      nodes.push(node);
      sortedMembers.forEach((member) => aliases.set(member.id, id));
    }
    return { nodes, aliases };
  }, [visibleNodes, data]);
  const nodeIds = useMemo(() => new Set(graphNodes.nodes.map((node) => node.id)), [graphNodes]);
  const visibleEdges = useMemo(() => {
    const grouped = new Map();
    for (const edge of data?.edges || []) {
      const source = graphNodes.aliases.get(edge.source) || edge.source;
      const target = graphNodes.aliases.get(edge.target) || edge.target;
      if (!nodeIds.has(source) || !nodeIds.has(target)) continue;
      const key = `${edge.relationship}|${source}|${target}`;
      if (!grouped.has(key)) {
        grouped.set(key, {
          ...edge,
          id: key,
          source,
          target,
          metadata: { ...(edge.metadata || {}), evidence_count: 0, evidence_items: [] },
        });
      }
      const merged = grouped.get(key);
      merged.metadata.evidence_count += 1;
      merged.metadata.evidence_items.push({ edge_id: edge.id, ...(edge.metadata || {}) });
    }
    return [...grouped.values()];
  }, [data, graphNodes, nodeIds]);
  const layout = useMemo(() => {
    const width = Math.max(1000, canvasWidth);
    const columns = { source_ip: 0, session: 1, command: 2, alert: 3, technique: 4 };
    const perType = Object.fromEntries(TYPES.map((type) => [type, graphNodes.nodes.filter((node) => node.type === type)]));
    const maxRows = Math.max(1, ...Object.values(perType).map((items) => items.length));
    const height = Math.max(540, 70 + maxRows * 64);
    const positions = new Map();
    for (const type of TYPES) {
      const items = perType[type].map((node, index) => {
        const connectedRows = visibleEdges
          .filter((edge) => edge.target === node.id && positions.has(edge.source))
          .map((edge) => positions.get(edge.source).row / Math.max(1, positions.get(edge.source).count - 1));
        return { node, index, barycenter: connectedRows.length
          ? connectedRows.reduce((total, value) => total + value, 0) / connectedRows.length
          : null };
      }).sort((left, right) => {
        if (left.barycenter !== null && right.barycenter === null) return -1;
        if (left.barycenter === null && right.barycenter !== null) return 1;
        if (left.barycenter !== null && right.barycenter !== null && left.barycenter !== right.barycenter) {
          return left.barycenter - right.barycenter;
        }
        return String(left.node.label).localeCompare(String(right.node.label)) || left.index - right.index;
      }).map(({ node }) => node);
      items.forEach((node, index) => positions.set(node.id, {
        x: 60 + columns[type] * ((width - 240) / 4),
        y: 40 + (index + 1) * (height - 80) / (items.length + 1),
        row: index,
        count: items.length,
      }));
    }
    return { positions, height, width };
  }, [graphNodes, visibleEdges, canvasWidth]);

  useEffect(() => {
    let active = true;
    async function loadSelectedDetail() {
      setDetail(null);
      setDetailError("");
      if (!selected || !["alert", "technique"].includes(selected.type)) {
        setDetailLoading(false);
        return undefined;
      }
      const key = selected.type === "alert" ? selectedAlertId : selected.metadata?.technique_id;
      if (!key) {
        setDetailLoading(false);
        return undefined;
      }
      setDetailLoading(true);
      const params = { ...filters };
      if (!params.start) delete params.start;
      if (!params.end) delete params.end;
      if (!params.behavior) delete params.behavior;
      try {
        const path = selected.type === "alert" ? `/api/alerts/${encodeURIComponent(key)}` : `/api/mitre/techniques/${encodeURIComponent(key)}`;
        const response = await axios.get(`${API}${path}`, { params });
        if (active) setDetail(response.data);
      } catch (err) {
        if (active) setDetailError(err.response?.data?.detail || "Unable to load the selected evidence detail.");
      } finally {
        if (active) setDetailLoading(false);
      }
    }
    loadSelectedDetail();
    return () => { active = false; };
  }, [selected, selectedAlertId, filters]);

  function selectNode(node) {
    setSelected(node);
    setSelectedAlertId(node.type === "alert" && node.metadata?.alert_count === 1
      ? node.metadata.alerts?.[0]?.alert_id || ""
      : "");
    setDetail(null);
    setDetailError("");
    if (node.type === "source_ip") onSelectAttacker?.(node.metadata?.source_ip || node.label);
  }

  function selectAlertMember(alert) {
    if (alert.alert_id === selectedAlertId) return;
    setSelectedAlertId(alert.alert_id || "");
    setDetail(null);
    setDetailError("");
  }

  function fitGraph() { setZoom(1); setOffset({ x: 0, y: 0 }); }
  function handlePointerDown(event) {
    if (event.target.closest?.(".attack-graph-node")) return;
    drag.current = { x: event.clientX - offset.x, y: event.clientY - offset.y };
    event.currentTarget.setPointerCapture(event.pointerId);
  }
  function handlePointerMove(event) {
    if (drag.current) setOffset({ x: event.clientX - drag.current.x, y: event.clientY - drag.current.y });
  }
  const alertRecordCount = graphNodes.nodes.reduce((total, node) =>
    total + (node.type === "alert" ? node.metadata?.alert_count || 1 : 0), 0);

  const graphPanel = (
    <section className={`panel attack-graph-panel${isFullscreen ? " is-fullscreen" : ""}`} role={isFullscreen ? "dialog" : undefined} aria-modal={isFullscreen || undefined} aria-label={isFullscreen ? "Expanded Attack Relationship Graph" : undefined}>
      {isFullscreen && <div className="attack-graph-fullscreen-header"><div><strong>Attack Relationship Graph</strong><span>Expanded investigation view</span></div><button ref={closeFullscreenButtonRef} type="button" className="attack-graph-exit-fullscreen" onClick={exitFullscreen}>Close fullscreen</button></div>}
      <div className="panel-header"><div><h3>Attack Relationship Graph</h3><p>Recorded relationships among source IPs, sessions, commands, alerts, and mapped ATT&amp;CK evidence.</p></div></div>
      <div className="attack-graph-controls">
        <label>Search nodes<input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="IP, session, command, alert, technique" /></label>
        <label>Focus source IP<input value={focusIp} onChange={(event) => { setFocusIp(event.target.value); setFocusSession(""); }} placeholder="Optional IP" /></label>
        <label>Focus session<input value={focusSession} onChange={(event) => { setFocusSession(event.target.value); setFocusIp(""); }} placeholder="Optional session ID" /></label>
        <button type="button" onClick={() => { setFocusIp(""); setFocusSession(""); }}>Reset focus</button>
      </div>
      <div className="attack-graph-type-filters" aria-label="Graph node types">
        {TYPES.map((type) => <label key={type}><input type="checkbox" checked={enabledTypes.includes(type)} onChange={() => setEnabledTypes((current) => current.includes(type) ? current.filter((value) => value !== type) : [...current, type])} /><i style={{ background: COLORS[type] }} />{LABELS[type]}</label>)}
      </div>
      {error && <div className="error-banner">{error}</div>}
      <div className="attack-graph-layout">
        <div className="attack-graph-canvas-wrap" ref={canvasWrapRef}>
          <div className="attack-graph-toolbar">
            <span>{loading ? "Updating graph…" : `${graphNodes.nodes.length} visual nodes · ${visibleEdges.length} relationships${alertRecordCount ? ` · ${alertRecordCount} alerts` : ""}`}</span>
            <div><button type="button" aria-label="Zoom out" onClick={() => setZoom((value) => Math.max(0.55, value - 0.15))}>−</button><button type="button" aria-label="Zoom in" onClick={() => setZoom((value) => Math.min(2.5, value + 0.15))}>+</button><button type="button" onClick={fitGraph}>Fit / reset</button><button ref={expandButtonRef} type="button" className="attack-graph-expand-button" aria-label={isFullscreen ? "Exit fullscreen" : "Expand graph"} title={isFullscreen ? "Exit fullscreen" : "Expand graph"} onClick={() => isFullscreen ? exitFullscreen() : setIsFullscreen(true)}><svg aria-hidden="true" viewBox="0 0 16 16"><path d="M2 6V2h4M10 2h4v4M14 10v4h-4M6 14H2v-4" /></svg><span>{isFullscreen ? "Exit" : "Expand"}</span></button></div>
          </div>
          {loading && !data ? <div className="empty-state">Loading relationship evidence…</div> : error && !data ? <div className="empty-state">Graph unavailable. See the error above.</div> : graphNodes.nodes.length ? (
            <svg className="attack-graph-svg" width={layout.width} height={layout.height} viewBox={`0 0 ${layout.width} ${layout.height}`} role="img" aria-label="Interactive attack relationship graph" onWheel={(event) => { event.preventDefault(); setZoom((value) => Math.max(0.55, Math.min(2.5, value + (event.deltaY < 0 ? 0.08 : -0.08)))); }} onPointerDown={handlePointerDown} onPointerMove={handlePointerMove} onPointerUp={() => { drag.current = null; }} onPointerCancel={() => { drag.current = null; }}>
              <defs><marker id="attack-graph-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#52647a" /></marker></defs>
              <g transform={`translate(${offset.x} ${offset.y}) scale(${zoom})`}>
                {visibleEdges.map((edge) => { const a = layout.positions.get(edge.source); const b = layout.positions.get(edge.target); const count = edge.metadata?.evidence_count || 1; return a && b ? <g key={edge.id}><line x1={a.x} y1={a.y} x2={b.x} y2={b.y} className="attack-graph-edge" strokeWidth={count > 1 ? Math.min(3, 1.5 + Math.log2(count) * 0.35) : undefined} markerEnd="url(#attack-graph-arrow)" /><title>{edge.relationship}{count > 1 ? ` (${count} recorded relationships grouped)` : ""}: {edge.metadata?.explanation || "Recorded evidence relationship"}</title></g> : null; })}
                {graphNodes.nodes.map((node) => {
                  const p = layout.positions.get(node.id);
                  if (!p) return null;
                  const lines = wrapGraphLabel(node.label, 22);
                  const alertCount = node.type === "alert" ? node.metadata?.alert_count || 1 : 0;
                  return (
                    <g className="attack-graph-node" key={node.id} transform={`translate(${p.x} ${p.y})`} role="button" tabIndex={0} onClick={() => selectNode(node)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") selectNode(node); }}>
                      <circle r={node.type === "source_ip" ? 13 : 10} fill={COLORS[node.type]} className={selected?.id === node.id ? "selected" : ""} />
                      <text x={17} y={4 - 7 * (lines.length - 1)}>{lines.map((line, index) => <tspan key={`${node.id}-label-${index}`} x={17} dy={index === 0 ? 0 : 14}>{line}</tspan>)}</text>
                      {alertCount > 1 && <g className="attack-graph-alert-count"><rect x="-22" y="-23" width="44" height="15" rx="7.5" /><text x="0" y="-12" textAnchor="middle">×{alertCount}</text></g>}
                      <title>{LABELS[node.type]} · {node.label}</title>
                    </g>
                  );
                })}
              </g>
            </svg>
          ) : <div className="empty-state">No graph relationships match the current filters.</div>}
        </div>
        <aside className="attack-graph-detail">
          <div className="attack-graph-detail-title">SELECTED EVIDENCE</div>
          {!selected ? <p>Select a node to inspect its recorded details.</p> : <>
            <span className="attack-graph-node-type" style={{ color: COLORS[selected.type] }}>{LABELS[selected.type]}</span>
            <h4>{selected.label}</h4>
            {selected.type === "alert" && selected.metadata?.alert_count > 1 && <span className="attack-graph-alert-group-count">{selected.metadata.alert_count} individual alerts</span>}
            {selected.type === "source_ip" && <button type="button" className="source-ip-button" onClick={() => onSelectAttacker?.(selected.metadata?.source_ip || selected.label)}>Open attacker profile</button>}
            {selected.type === "session" && <EvidenceList metadata={selected.metadata} />}
            {selected.type === "command" && <EvidenceList metadata={selected.metadata} />}
            {selected.type === "alert" && <>
              {selected.metadata?.alert_count > 1 && <div className="attack-graph-alert-group">
                <p>{selected.metadata.alert_count} individual alerts share this rule title. Select a record to inspect its evidence; each underlying alert remains separate.</p>
                <div className="attack-graph-alert-members">{selected.metadata.alerts.map((alert) => <button type="button" key={alert.alert_id} aria-pressed={selectedAlertId === alert.alert_id} onClick={() => selectAlertMember(alert)}>
                  <strong>{alert.source_ip || "Source unavailable"}</strong>
                  <span>{alert.severity || "Severity unavailable"} · {Number(alert.event_count || 0).toLocaleString()} events</span>
                  <small>{alert.first_seen || "Timestamp unavailable"}{alert.last_seen && alert.last_seen !== alert.first_seen ? ` — ${alert.last_seen}` : ""} · {alert.session_ids?.length || 0} sessions</small>
                </button>)}</div>
              </div>}
              {selected.metadata?.alert_count > 1 && !selectedAlertId
                ? <p className="attack-graph-detail-state">Choose an alert record above to load its full details.</p>
                : detailLoading ? <p className="attack-graph-detail-state">Loading alert evidence…</p> : detailError ? <p className="attacker-profile-error">{detailError}</p> : detail ? <><p>{detail.severity_rationale}</p><EvidenceList metadata={{ severity: detail.severity, source_ip: detail.source_ip, first_seen: detail.first_seen, last_seen: detail.last_seen, session_ids: detail.session_ids, event_count: detail.event_count, supporting_event_counts: detail.supporting_event_counts, evidence: detail.evidence }} />{detail.source_ip && <button type="button" className="source-ip-button" onClick={() => onSelectAttacker?.(detail.source_ip)}>Open attacker profile: {detail.source_ip}</button>}</> : <EvidenceList metadata={selected.metadata} />}
            </>}
            {selected.type === "technique" && (detailLoading ? <p className="attack-graph-detail-state">Loading technique evidence…</p> : detailError ? <p className="attacker-profile-error">{detailError}</p> : detail ? <><p>{detail.rationale}</p><EvidenceList metadata={{ technique_id: detail.technique_id, tactic: detail.tactic, confidence: detail.confidence, first_seen: detail.first_seen, last_seen: detail.last_seen, event_count: detail.event_count, evidence_examples: detail.evidence_examples, sources: detail.sources?.map((source) => source.src_ip) }} />{detail.official_url && <a href={detail.official_url} target="_blank" rel="noreferrer">Official MITRE ATT&amp;CK entry</a>}{detail.sources?.slice(0, 10).map((source) => <button className="source-ip-button" type="button" key={source.src_ip} onClick={() => onSelectAttacker?.(source.src_ip)}>Open {source.src_ip}</button>)}</> : <EvidenceList metadata={selected.metadata} />)}
          </>}
          {data?.scope?.truncated && <small className="attack-graph-note">Graph is bounded to a recent session sample. Focus an IP or session to inspect more detail.</small>}
        </aside>
      </div>
      <div className="attack-graph-legend">{TYPES.map((type) => <span key={type}><i style={{ background: COLORS[type] }} />{LABELS[type]}</span>)}</div>
      <p className="attack-graph-note">Alerts with the same rule title are grouped visually; select a member in the evidence panel to open its individual recorded evidence.</p>
      <p className="attack-graph-note">Edges represent recorded source/session membership, commands recorded in sessions, alert evidence scope, or explicit output from the existing ATT&amp;CK mapper. They do not indicate communication or common ownership between attackers.</p>
    </section>
  );

  return isFullscreen && typeof document !== "undefined"
    ? createPortal(graphPanel, document.body)
    : graphPanel;
}

function wrapGraphLabel(label, maxChars = 24, maxLines = 3) {
  const words = String(label || "").trim().split(/\s+/).filter(Boolean);
  const lines = [];
  let line = "";

  for (const originalWord of words) {
    let word = originalWord;
    while (word.length > maxChars) {
      if (line) {
        lines.push(line);
        line = "";
      }
      lines.push(word.slice(0, maxChars));
      word = word.slice(maxChars);
    }
    if (line && `${line} ${word}`.length > maxChars) {
      lines.push(line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) lines.push(line);
  if (!lines.length) return ["Unknown node"];
  if (lines.length <= maxLines) return lines;

  const finalLine = lines.slice(maxLines - 1).join(" ");
  return [...lines.slice(0, maxLines - 1), `${finalLine.slice(0, maxChars - 1)}…`];
}

function EvidenceList({ metadata }) {
  const entries = Object.entries(metadata || {}).filter(([, value]) => value !== null && value !== undefined && value !== "");
  return entries.length
    ? <dl className="attack-graph-evidence">{entries.map(([key, value]) => <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd><EvidenceValue value={value} /></dd></div>)}</dl>
    : <p className="attack-graph-evidence-empty">No additional recorded evidence is available.</p>;
}

function EvidenceValue({ value }) {
  if (value === null || value === undefined || value === "") {
    return <span className="attack-graph-evidence-empty">Not available</span>;
  }
  if (Array.isArray(value)) {
    return value.length
      ? <ul className="attack-graph-evidence-list">{value.map((item, index) => <li key={`${String(item)}-${index}`}><EvidenceValue value={item} /></li>)}</ul>
      : <span className="attack-graph-evidence-empty">Not available</span>;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value).filter(([, item]) => item !== null && item !== undefined && item !== "");
    return entries.length
      ? <dl className="attack-graph-evidence-nested">{entries.map(([key, item]) => <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd><EvidenceValue value={item} /></dd></div>)}</dl>
      : <span className="attack-graph-evidence-empty">Not available</span>;
  }
  return String(value);
}
