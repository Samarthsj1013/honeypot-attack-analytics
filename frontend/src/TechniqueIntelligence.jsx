import { useEffect, useState } from "react";
import axios from "axios";
import { AlertTriangle } from "lucide-react";

import { API } from "./api";

function ConfidenceBadge({ level }) {
  return <span className={`confidence-badge ${String(level || "").toLowerCase()}`}>{level}</span>;
}

function Panel({ title, subtitle, children }) {
  return <section className="panel">
    <div className="panel-header"><div><h2>{title}</h2><p>{subtitle}</p></div></div>
    {children}
  </section>;
}

function EmptyState({ text }) {
  return <div className="empty-state">{text}</div>;
}

function TechniqueIntelligence({ filters, onSelectAttacker }) {
  const [techniqueFilter, setTechniqueFilter] = useState("");
  const [tactic, setTactic] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [page, setPage] = useState(0);
  const [selectedTechnique, setSelectedTechnique] = useState("");
  const [detailOffset, setDetailOffset] = useState(0);
  const [data, setData] = useState(null);
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState("");
  const [detailError, setDetailError] = useState("");
  const pageSize = 25;
  const detailPageSize = 100;

  useEffect(() => {
    setPage(0);
    setDetailOffset(0);
    setSelectedTechnique("");
  }, [filters, techniqueFilter, tactic, sourceIp]);

  useEffect(() => {
    let active = true;
    async function loadTechniques() {
      try {
        setLoading(true);
        setError("");
        const params = { limit: pageSize, offset: page * pageSize, ...filters };
        if (!params.start) delete params.start;
        if (!params.end) delete params.end;
        if (!params.behavior) delete params.behavior;
        if (techniqueFilter.trim()) params.technique_id = techniqueFilter.trim();
        if (tactic) params.tactic = tactic;
        if (sourceIp.trim()) params.source_ip = sourceIp.trim();
        const response = await axios.get(`${API}/api/mitre/techniques`, { params });
        if (!Array.isArray(response.data?.items)) throw new Error("Unexpected technique intelligence response");
        if (active) setData(response.data);
      } catch (err) {
        console.error("Failed to load MITRE technique intelligence:", err);
        if (active) {
          setData(null);
          setError(err.response?.data?.detail || "Unable to load technique intelligence.");
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    loadTechniques();
    return () => { active = false; };
  }, [filters, techniqueFilter, tactic, sourceIp, page]);

  useEffect(() => {
    if (!selectedTechnique) {
      setDetail(null);
      return undefined;
    }
    let active = true;
    async function loadDetail() {
      try {
        setDetailLoading(true);
        setDetailError("");
        const params = { limit: detailPageSize, offset: detailOffset, ...filters };
        if (!params.start) delete params.start;
        if (!params.end) delete params.end;
        if (!params.behavior) delete params.behavior;
        if (sourceIp.trim()) params.source_ip = sourceIp.trim();
        const response = await axios.get(
          `${API}/api/mitre/techniques/${encodeURIComponent(selectedTechnique)}`, { params }
        );
        if (!Array.isArray(response.data?.sources)) throw new Error("Unexpected technique detail response");
        if (active) setDetail(response.data);
      } catch (err) {
        console.error("Failed to load technique evidence:", err);
        if (active) {
          setDetail(null);
          setDetailError(err.response?.status === 404
            ? "No evidence for this technique matches the active filters."
            : "Unable to load technique evidence.");
        }
      } finally {
        if (active) setDetailLoading(false);
      }
    }
    loadDetail();
    return () => { active = false; };
  }, [selectedTechnique, detailOffset, filters, sourceIp]);

  const summary = data?.summary || {};
  return (
    <div className="mitre-intelligence">
      <Panel title="MITRE ATT&CK Technique Intelligence" subtitle="Observed honeypot evidence mapped to a small offline ATT&CK catalog. Mappings are behavioral inferences, not attribution or proof of real-system compromise.">
        <div className="mitre-summary-grid">
          {[["Mapped techniques", summary.mapped_techniques], ["Observed tactics", summary.observed_tactics], ["Source IPs", summary.source_ips]].map(([label, value]) => (
            <div className="source-overview-card" key={label}><span>{label}</span><strong>{loading && !data ? "—" : Number(value || 0).toLocaleString()}</strong></div>
          ))}
        </div>
        <div className="mitre-filter-bar">
          <label>Technique ID<input value={techniqueFilter} onChange={(event) => setTechniqueFilter(event.target.value)} placeholder="e.g. T1082" /></label>
          <label>Tactic<select value={tactic} onChange={(event) => setTactic(event.target.value)}>
            <option value="">All tactics</option>
            {["Credential Access", "Command and Control", "Discovery", "Execution"].map((value) => <option key={value}>{value}</option>)}
          </select></label>
          <label>Source IP<input value={sourceIp} onChange={(event) => setSourceIp(event.target.value)} placeholder="Filter by IP" /></label>
          {(techniqueFilter || tactic || sourceIp) && <button type="button" onClick={() => { setTechniqueFilter(""); setTactic(""); setSourceIp(""); setPage(0); }}>Clear filters</button>}
          {loading && <span className="source-loading">Updating mappings…</span>}
        </div>
        {error && <div className="error-banner"><AlertTriangle size={18} /><span>{error}</span></div>}
        {data?.scope_note && <p className="mitre-scope-note">{data.scope_note}</p>}
        {!error && data && (data.items.length ? <>
          <div className="table-wrapper mitre-table-wrapper"><table className="source-table mitre-table">
            <thead><tr><th>TECHNIQUE</th><th>TACTIC</th><th>EVIDENCE EVENTS</th><th>SOURCE IPS</th><th>CONFIDENCE</th></tr></thead>
            <tbody>{data.items.map((item) => <tr key={item.technique_id} className={selectedTechnique === item.technique_id ? "source-row-selected" : ""}>
              <td><button type="button" className="mitre-technique-button" onClick={() => { setSelectedTechnique(item.technique_id); setDetailOffset(0); }}><strong>{item.technique_id}</strong><span>{item.name}</span></button></td>
              <td>{item.tactic}</td><td>{item.event_count.toLocaleString()}</td><td>{item.source_count.toLocaleString()}</td><td><ConfidenceBadge level={item.confidence} /></td>
            </tr>)}</tbody>
          </table></div>
          <div className="source-pagination"><span>{data.total.toLocaleString()} technique mappings · page {page + 1}</span>
            <button type="button" disabled={page === 0 || loading} onClick={() => setPage((current) => Math.max(0, current - 1))}>Previous</button>
            <button type="button" disabled={!data.has_more || loading} onClick={() => setPage((current) => current + 1)}>Next</button>
          </div>
        </> : <EmptyState text="No ATT&CK technique evidence matches these filters." />)}
        {selectedTechnique && <div className="mitre-detail">
          {detailLoading ? <div className="attacker-profile-loading">Loading technique evidence…</div>
            : detailError ? <div className="attacker-profile-error">{detailError}</div>
              : detail && <>
                <div className="mitre-detail-heading"><div><span>{detail.technique_id} · {detail.tactic}</span><h3>{detail.name}</h3><a href={detail.official_url} target="_blank" rel="noreferrer">Official MITRE ATT&amp;CK entry</a></div><ConfidenceBadge level={detail.confidence} /></div>
                <p className="mitre-rationale">{detail.rationale}</p>
                <div className="mitre-detail-meta"><span>Observed {detail.event_count} matching events</span><span>{detail.first_seen || "Timestamp unavailable"} — {detail.last_seen || "Timestamp unavailable"}</span><span>Confidence: {detail.confidence_rule}</span></div>
                <div className="mitre-evidence-list"><strong>Recorded evidence examples</strong>{detail.evidence_examples.map((example, index) => <code key={`${example}-${index}`}>{example}</code>)}</div>
                <div className="table-wrapper"><table className="source-table mitre-source-table">
                  <thead><tr><th>SOURCE IP</th><th>EVENTS</th><th>SESSIONS</th><th>FIRST / LAST SEEN</th><th>OBSERVED EVIDENCE</th></tr></thead>
                  <tbody>{detail.sources.map((source) => <tr key={source.src_ip}>
                    <td><button type="button" className="source-ip-button" onClick={() => onSelectAttacker(source.src_ip)}>{source.src_ip}</button></td>
                    <td>{source.event_count}</td><td>{source.session_ids.join(", ") || "Unavailable"}</td>
                    <td>{source.first_seen || "—"}<br />{source.last_seen || "—"}</td><td>{source.evidence_examples.join(" · ") || source.event_types.join(", ")}</td>
                  </tr>)}</tbody>
                </table></div>
                {detail.total_sources > detailPageSize && <div className="source-pagination"><span>{detail.total_sources} source IPs</span>
                  <button type="button" disabled={detailOffset === 0 || detailLoading} onClick={() => setDetailOffset((current) => Math.max(0, current - detailPageSize))}>Previous</button>
                  <button type="button" disabled={!detail.has_more || detailLoading} onClick={() => setDetailOffset((current) => current + detailPageSize)}>Next</button>
                </div>}
              </>}
        </div>}
      </Panel>
    </div>
  );
}

export default TechniqueIntelligence;
