import { useEffect, useMemo, useRef, useState } from "react";
import axios from "axios";

const API = "http://127.0.0.1:8000";
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
  const [detail, setDetail] = useState(null);
  const [detailError, setDetailError] = useState("");
  const [zoom, setZoom] = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const drag = useRef(null);

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
  const nodeIds = useMemo(() => new Set(visibleNodes.map((node) => node.id)), [visibleNodes]);
  const layout = useMemo(() => {
    const columns = { source_ip: 0, session: 1, command: 2, alert: 3, technique: 4 };
    const perType = Object.fromEntries(TYPES.map((type) => [type, visibleNodes.filter((node) => node.type === type)]));
    const maxRows = Math.max(1, ...Object.values(perType).map((items) => items.length));
    const height = Math.max(540, 70 + maxRows * 78);
    const positions = new Map();
    for (const type of TYPES) {
      const items = perType[type];
      items.forEach((node, index) => positions.set(node.id, {
        x: 100 + columns[type] * 250,
        y: 40 + (index + 1) * (height - 80) / (items.length + 1),
      }));
    }
    return { positions, height };
  }, [visibleNodes]);
  const visibleEdges = (data?.edges || []).filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target));

  useEffect(() => {
    let active = true;
    async function loadSelectedDetail() {
      setDetail(null);
      setDetailError("");
      if (!selected || !["alert", "technique"].includes(selected.type)) return;
      const key = selected.type === "alert" ? selected.metadata?.alert_id : selected.metadata?.technique_id;
      if (!key) return;
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
      }
    }
    loadSelectedDetail();
    return () => { active = false; };
  }, [selected, filters]);

  function selectNode(node) {
    setSelected(node);
    setDetail(null);
    setDetailError("");
    if (node.type === "source_ip") onSelectAttacker?.(node.metadata?.source_ip || node.label);
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

  return (
    <section className="panel attack-graph-panel">
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
        <div className="attack-graph-canvas-wrap">
          <div className="attack-graph-toolbar">
            <span>{loading ? "Updating graph…" : `${visibleNodes.length} nodes · ${visibleEdges.length} relationships`}</span>
            <div><button type="button" aria-label="Zoom out" onClick={() => setZoom((value) => Math.max(0.55, value - 0.15))}>−</button><button type="button" aria-label="Zoom in" onClick={() => setZoom((value) => Math.min(2.5, value + 0.15))}>+</button><button type="button" onClick={fitGraph}>Fit / reset</button></div>
          </div>
          {loading && !data ? <div className="empty-state">Loading relationship evidence…</div> : visibleNodes.length ? (
            <svg className="attack-graph-svg" viewBox={`0 0 1100 ${layout.height}`} role="img" aria-label="Interactive attack relationship graph" onWheel={(event) => { event.preventDefault(); setZoom((value) => Math.max(0.55, Math.min(2.5, value + (event.deltaY < 0 ? 0.08 : -0.08)))); }} onPointerDown={handlePointerDown} onPointerMove={handlePointerMove} onPointerUp={() => { drag.current = null; }} onPointerCancel={() => { drag.current = null; }}>
              <defs><marker id="attack-graph-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#52647a" /></marker></defs>
              <g transform={`translate(${offset.x} ${offset.y}) scale(${zoom})`}>
                {visibleEdges.map((edge) => { const a = layout.positions.get(edge.source); const b = layout.positions.get(edge.target); return a && b ? <g key={edge.id}><line x1={a.x} y1={a.y} x2={b.x} y2={b.y} className="attack-graph-edge" markerEnd="url(#attack-graph-arrow)" /><title>{edge.relationship}: {edge.metadata?.explanation}</title></g> : null; })}
                {visibleNodes.map((node) => { const p = layout.positions.get(node.id); if (!p) return null; return <g className="attack-graph-node" key={node.id} transform={`translate(${p.x} ${p.y})`} role="button" tabIndex={0} onClick={() => selectNode(node)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") selectNode(node); }}><circle r={node.type === "source_ip" ? 13 : 10} fill={COLORS[node.type]} className={selected?.id === node.id ? "selected" : ""} /><text x={17} y={4}>{node.label.length > 30 ? `${node.label.slice(0, 27)}…` : node.label}</text><title>{LABELS[node.type]} · {node.label}</title></g>; })}
              </g>
            </svg>
          ) : <div className="empty-state">No graph relationships match the current filters.</div>}
        </div>
        <aside className="attack-graph-detail">
          <div className="attack-graph-detail-title">SELECTED EVIDENCE</div>
          {!selected ? <p>Select a node to inspect its recorded details.</p> : <>
            <span className="attack-graph-node-type" style={{ color: COLORS[selected.type] }}>{LABELS[selected.type]}</span>
            <h4>{selected.label}</h4>
            {selected.type === "source_ip" && <button type="button" className="source-ip-button" onClick={() => onSelectAttacker?.(selected.metadata?.source_ip || selected.label)}>Open attacker profile</button>}
            {selected.type === "session" && <EvidenceList metadata={selected.metadata} />}
            {selected.type === "command" && <EvidenceList metadata={selected.metadata} />}
            {selected.type === "alert" && (detailError ? <p className="attacker-profile-error">{detailError}</p> : detail ? <><p>{detail.severity_rationale}</p><EvidenceList metadata={{ severity: detail.severity, source_ip: detail.source_ip, first_seen: detail.first_seen, last_seen: detail.last_seen, session_ids: detail.session_ids, event_count: detail.event_count, evidence: detail.evidence }} />{detail.source_ip && <button type="button" className="source-ip-button" onClick={() => onSelectAttacker?.(detail.source_ip)}>Open attacker profile: {detail.source_ip}</button>}</> : <EvidenceList metadata={selected.metadata} />)}
            {selected.type === "technique" && (detailError ? <p className="attacker-profile-error">{detailError}</p> : detail ? <><p>{detail.rationale}</p><EvidenceList metadata={{ technique_id: detail.technique_id, tactic: detail.tactic, confidence: detail.confidence, first_seen: detail.first_seen, last_seen: detail.last_seen, event_count: detail.event_count, evidence_examples: detail.evidence_examples, sources: detail.sources?.map((source) => source.src_ip) }} />{detail.official_url && <a href={detail.official_url} target="_blank" rel="noreferrer">Official MITRE ATT&amp;CK entry</a>}{detail.sources?.slice(0, 10).map((source) => <button className="source-ip-button" type="button" key={source.src_ip} onClick={() => onSelectAttacker?.(source.src_ip)}>Open {source.src_ip}</button>)}</> : <EvidenceList metadata={selected.metadata} />)}
          </>}
          {data?.scope?.truncated && <small className="attack-graph-note">Graph is bounded to a recent session sample. Focus an IP or session to inspect more detail.</small>}
        </aside>
      </div>
      <div className="attack-graph-legend">{TYPES.map((type) => <span key={type}><i style={{ background: COLORS[type] }} />{LABELS[type]}</span>)}</div>
      <p className="attack-graph-note">Edges represent recorded source/session membership, commands recorded in sessions, alert evidence scope, or explicit output from the existing ATT&amp;CK mapper. They do not indicate communication or common ownership between attackers.</p>
    </section>
  );
}

function EvidenceList({ metadata }) {
  return <dl className="attack-graph-evidence">{Object.entries(metadata || {}).filter(([, value]) => value !== null && value !== undefined && value !== "").map(([key, value]) => <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{Array.isArray(value) ? value.join(", ") : typeof value === "object" ? JSON.stringify(value) : String(value)}</dd></div>)}</dl>;
}
