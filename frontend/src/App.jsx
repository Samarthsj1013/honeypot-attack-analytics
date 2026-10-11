import { useEffect, useRef, useState } from "react";

import axios from "axios";

import {

  MapContainer,

  TileLayer,

  CircleMarker,

  Popup,

  useMap,

} from "react-leaflet";

import "leaflet/dist/leaflet.css";

import {

  Activity,

  AlertTriangle,

  Bot,

  KeyRound,

  Globe,

  Shield,

  ShieldAlert,

  Users,

} from "lucide-react";

import {

  Bar,

  BarChart,

  CartesianGrid,

  Cell,

  Legend,

  Line,

  LineChart,

  Pie,

  PieChart,

  ResponsiveContainer,

  Tooltip,

  XAxis,

  YAxis,

} from "recharts";

const API = "http://127.0.0.1:8000";

function KpiCard({ icon, label, value, danger, success }) {

  return (

    <div className="kpi-card">

      <div

        className={`kpi-icon ${danger ? "danger" : ""} ${

          success ? "success" : ""

        }`}

      >

        {icon}

      </div>

      <div className="kpi-content">

        <div className="kpi-label">{label}</div>

        <div className="kpi-value">

          {value === null || value === undefined

            ? "—"

            : value.toLocaleString()}

        </div>

      </div>

    </div>

  );

}

function RiskBadge({ level }) {

  return (

    <span className={`risk-badge ${String(level || "").toLowerCase()}`}>

      {level}

    </span>

  );

}

function App() {

  const [meta, setMeta] = useState(null);

  const [overview, setOverview] = useState(null);

  const [timeline, setTimeline] = useState([]);

  const [behaviorData, setBehaviorData] = useState([]);

  const [riskData, setRiskData] = useState([]);

  const [attackers, setAttackers] = useState([]);

  const [hourlyData, setHourlyData] = useState([]);

  const [usernames, setUsernames] = useState([]);

  const [passwords, setPasswords] = useState([]);

  const [commands, setCommands] = useState([]);

  const [startDate, setStartDate] = useState("");

  const [endDate, setEndDate] = useState("");

  const [selectedBehavior, setSelectedBehavior] = useState("");

  const [filters, setFilters] = useState({

    start: "",

    end: "",

    behavior: "",

  });

  const [loading, setLoading] = useState(true);

  const [error, setError] = useState("");

  const buildParams = () => {

    const params = {};

    if (filters.start) {

      params.start = filters.start;

    }

    if (filters.end) {

      params.end = filters.end;

    }

    if (filters.behavior) {

      params.behavior = filters.behavior;

    }

    return params;

  };

  useEffect(() => {

    async function loadMeta() {

      try {

        const response = await axios.get(`${API}/api/meta`);

        setMeta(response.data);

      } catch (err) {

        console.error("Failed to load metadata:", err);

      }

    }

    loadMeta();

  }, []);

  useEffect(() => {

    async function loadDashboard() {

      try {

        setLoading(true);

        setError("");

        const params = buildParams();

        const [

          overviewRes,

          timelineRes,

          behaviorRes,

          riskRes,

          attackersRes,

          hourlyRes,

          usernamesRes,

          passwordsRes,

          commandsRes,

        ] = await Promise.all([

          axios.get(`${API}/api/overview`, { params }),

          axios.get(`${API}/api/timeline`, { params }),

          axios.get(`${API}/api/behaviors`, { params }),

          axios.get(`${API}/api/risk-levels`, { params }),

          axios.get(`${API}/api/attackers`, { params }),

          axios.get(`${API}/api/hourly`, { params }),

          axios.get(`${API}/api/credentials`, {

            params: {

              ...params,

              kind: "username",

            },

          }),

          axios.get(`${API}/api/credentials`, {

            params: {

              ...params,

              kind: "password",

            },

          }),

          axios.get(`${API}/api/credentials`, {

            params: {

              ...params,

              kind: "command",

            },

          }),

        ]);

        setOverview(overviewRes.data);

        setTimeline(timelineRes.data);

        setBehaviorData(behaviorRes.data);

        setRiskData(riskRes.data);

        setAttackers(attackersRes.data);

        setHourlyData(hourlyRes.data);

        setUsernames(usernamesRes.data);

        setPasswords(passwordsRes.data);

        setCommands(commandsRes.data);

      } catch (err) {

        console.error(err);

        if (err.response?.data?.detail) {

          setError(err.response.data.detail);

        } else {

          setError(

            "Unable to load dashboard data. Make sure the FastAPI server is running."

          );

        }

      } finally {

        setLoading(false);

      }

    }

    loadDashboard();

  }, [filters]);

  const applyFilters = () => {

    setFilters({

      start: startDate,

      end: endDate,

      behavior: selectedBehavior,

    });

  };

  const resetFilters = () => {

    setStartDate("");

    setEndDate("");

    setSelectedBehavior("");

    setFilters({

      start: "",

      end: "",

      behavior: "",

    });

  };

  const timelineChart = Object.values(

    timeline.reduce((acc, item) => {

      if (!acc[item.day]) {

        acc[item.day] = {

          day: item.day,

          sessions: 0,

        };

      }

      acc[item.day].sessions += item.sessions;

      return acc;

    }, {})

  );

  const riskChart = riskData.map((item) => ({

    name: item.risk_level,

    value: item.ips,

  }));

  const riskColors = {

    High: "#ef4444",

    Medium: "#f59e0b",

    Low: "#22c55e",

  };

  const formattedHourlyData = hourlyData.map((item) => ({

    ...item,

    hourLabel: `${String(item.hour).padStart(2, "0")}:00`,

  }));

  if (loading && !overview) {

    return (

      <div className="app-shell">

        <Sidebar />

        <main className="main-content">

          <div className="loading-screen">

            <div className="loading-spinner" />

            <p>Loading honeypot analytics...</p>

          </div>

        </main>

      </div>

    );

  }

  return (

    <div className="app-shell">

      <Sidebar />

      <main className="main-content">

        <header id="overview" className="dashboard-header">

          <div>

            <div className="eyebrow">SECURITY OPERATIONS</div>

            <h1>Honeypot Attack Overview</h1>

          </div>

          <div className="live-indicator">

            <span className="live-dot" />

            LIVE DATA

          </div>

        </header>

        <section className="monitoring-banner">

          <div>

            <div className="section-eyebrow">THREAT MONITORING</div>

            <h2>

              Attack activity across your honeypot infrastructure

            </h2>

          </div>

          <div className="time-range">

            <div>

              <span>First seen</span>

              <strong>

                {overview?.first_seen || meta?.first_day || "—"}

              </strong>

            </div>

            <div>

              <span>Last seen</span>

              <strong>

                {overview?.last_seen || meta?.last_day || "—"}

              </strong>

            </div>

          </div>

        </section>

        <section className="filter-bar">

          <div className="filter-group">

            <label>Start Date</label>

            <input

              type="date"

              value={startDate}

              min={meta?.first_day || ""}

              max={meta?.last_day || ""}

              onChange={(event) => setStartDate(event.target.value)}

            />

          </div>

          <div className="filter-group">

            <label>End Date</label>

            <input

              type="date"

              value={endDate}

              min={meta?.first_day || ""}

              max={meta?.last_day || ""}

              onChange={(event) => setEndDate(event.target.value)}

            />

          </div>

          <div className="filter-group">

            <label>Behavior</label>

            <select

              value={selectedBehavior}

              onChange={(event) =>

                setSelectedBehavior(event.target.value)

              }

            >

              <option value="">All Behaviors</option>

              {meta?.behaviors?.map((behavior) => (

                <option key={behavior} value={behavior}>

                  {behavior}

                </option>

              ))}

            </select>

          </div>

          <button

            className="filter-button"

            onClick={applyFilters}

          >

            Apply Filters

          </button>

          <button

            className="reset-button"

            onClick={resetFilters}

          >

            Reset

          </button>

        </section>

        {error && (

          <div className="error-banner">

            <AlertTriangle size={18} />

            <span>{error}</span>

          </div>

        )}

        {(filters.start || filters.end || filters.behavior) && (

          <div className="active-filter">

            <span>FILTERED VIEW</span>

            {filters.start && (

              <span>

                From <strong>{filters.start}</strong>

              </span>

            )}

            {filters.end && (

              <span>

                To <strong>{filters.end}</strong>

              </span>

            )}

            {filters.behavior && (

              <span>

                Behavior <strong>{filters.behavior}</strong>

              </span>

            )}

          </div>

        )}

        <section className="kpi-grid">

          <KpiCard

            icon={<Activity />}

            label="Total Events"

            value={overview?.total_events}

          />

          <KpiCard

            icon={<Bot />}

            label="Sessions"

            value={overview?.sessions}

          />

          <KpiCard

            icon={<Users />}

            label="Unique Attackers"

            value={overview?.unique_ips}

          />

          <KpiCard

            icon={<AlertTriangle />}

            label="Failed Logins"

            value={overview?.failed_logins}

            danger

          />

          <KpiCard

            icon={<ShieldAlert />}

            label="Successful Sessions"

            value={overview?.successful_sessions}

            success

          />

        </section>

        <section className="dashboard-grid two-columns">

          <Panel

            title="Attack Timeline"

            subtitle="Sessions by day"

          >

            <div className="chart-container">

              {timelineChart.length > 0 ? (

                <ResponsiveContainer width="100%" height={310}>

                  <LineChart data={timelineChart}>

                    <CartesianGrid

                      strokeDasharray="3 3"

                      stroke="#1c2a3b"

                    />

                    <XAxis

                      dataKey="day"

                      stroke="#61738e"

                      tick={{

                        fill: "#71839d",

                        fontSize: 11,

                      }}

                    />

                    <YAxis

                      stroke="#61738e"

                      tick={{

                        fill: "#71839d",

                        fontSize: 11,

                      }}

                    />

                    <Tooltip

                      contentStyle={{

                        background: "#0b1320",

                        border: "1px solid #24364b",

                        borderRadius: "8px",

                        color: "#fff",

                      }}

                    />

                    <Line

                      type="monotone"

                      dataKey="sessions"

                      stroke="#38bdf8"

                      strokeWidth={3}

                      dot={{

                        r: 3,

                        fill: "#38bdf8",

                      }}

                      activeDot={{

                        r: 6,

                      }}

                    />

                  </LineChart>

                </ResponsiveContainer>

              ) : (

                <EmptyState text="No timeline data for this filter." />

              )}

            </div>

          </Panel>

          <Panel

            title="Risk Distribution"

            subtitle="Attacker risk levels"

          >

            <div className="chart-container">

              {riskChart.length > 0 ? (

                <ResponsiveContainer width="100%" height={310}>

                  <PieChart>

                    <Pie

                      data={riskChart}

                      cx="50%"

                      cy="45%"

                      innerRadius={70}

                      outerRadius={105}

                      paddingAngle={4}

                      dataKey="value"

                      nameKey="name"

                    >

                      {riskChart.map((entry) => (

                        <Cell

                          key={entry.name}

                          fill={riskColors[entry.name]}

                        />

                      ))}

                    </Pie>

                    <Tooltip

                      contentStyle={{

                        background: "#0b1320",

                        border: "1px solid #24364b",

                        borderRadius: "8px",

                        color: "#fff",

                      }}

                    />

                    <Legend

                      verticalAlign="bottom"

                      formatter={(value) => (

                        <span

                          style={{

                            color: "#a8b7ca",

                          }}

                        >

                          {value}

                        </span>

                      )}

                    />

                  </PieChart>

                </ResponsiveContainer>

              ) : (

                <EmptyState text="No risk data for this filter." />

              )}

            </div>

          </Panel>

        </section>

        <section className="dashboard-grid">

          <Panel

            title="Attack Activity by Hour"

            subtitle="Sessions observed across the 24-hour period"

          >

            <div className="chart-container">

              {formattedHourlyData.length > 0 ? (

                <ResponsiveContainer width="100%" height={300}>

                  <BarChart data={formattedHourlyData}>

                    <CartesianGrid

                      strokeDasharray="3 3"

                      stroke="#1c2a3b"

                    />

                    <XAxis

                      dataKey="hourLabel"

                      stroke="#61738e"

                      tick={{

                        fill: "#71839d",

                        fontSize: 10,

                      }}

                    />

                    <YAxis

                      stroke="#61738e"

                      tick={{

                        fill: "#71839d",

                        fontSize: 11,

                      }}

                    />

                    <Tooltip

                      contentStyle={{

                        background: "#0b1320",

                        border: "1px solid #24364b",

                        borderRadius: "8px",

                        color: "#fff",

                      }}

                    />

                    <Bar

                      dataKey="sessions"

                      fill="#38bdf8"

                      radius={[5, 5, 0, 0]}

                    />

                  </BarChart>

                </ResponsiveContainer>

              ) : (

                <EmptyState text="No hourly activity for this filter." />

              )}

            </div>

          </Panel>

        </section>

        <section

          id="threat-intelligence"

          className="dashboard-grid two-columns"

        >

          <Panel

            title="Attack Behavior"

            subtitle="Session classification"

          >

            <div className="chart-container">

              {behaviorData.length > 0 ? (

                <ResponsiveContainer width="100%" height={330}>

                  <BarChart data={behaviorData}>

                    <CartesianGrid

                      strokeDasharray="3 3"

                      stroke="#1c2a3b"

                    />

                    <XAxis

                      dataKey="behavior"

                      stroke="#61738e"

                      tick={{

                        fill: "#71839d",

                        fontSize: 11,

                      }}

                    />

                    <YAxis

                      stroke="#61738e"

                      tick={{

                        fill: "#71839d",

                        fontSize: 11,

                      }}

                    />

                    <Tooltip

                      contentStyle={{

                        background: "#0b1320",

                        border: "1px solid #24364b",

                        borderRadius: "8px",

                        color: "#fff",

                      }}

                    />

                    <Bar

                      dataKey="sessions"

                      fill="#38bdf8"

                      radius={[6, 6, 0, 0]}

                    />

                  </BarChart>

                </ResponsiveContainer>

              ) : (

                <EmptyState text="No behavior data for this filter." />

              )}

            </div>

          </Panel>

          <Panel

            title="Top Attack Sources"

            subtitle="Highest activity IP addresses"

          >

            <AttackersTable attackers={attackers} />

          </Panel>

        </section>

        <section

          id="credentials"

          className="dashboard-grid three-columns"

        >

          <CredentialPanel

            title="Top Usernames"

            subtitle="Most attempted usernames"

            data={usernames}

            valueLabel="USERNAME"

          />

          <CredentialPanel

            title="Top Passwords"

            subtitle="Most attempted passwords"

            data={passwords}

            valueLabel="PASSWORD"

          />

          <CredentialPanel

            title="Top Commands"

            subtitle="Most observed commands"

            data={commands}

            valueLabel="COMMAND"

          />

        </section>

        <section id="attack-sources" className="dashboard-grid">
          <SourceIntelligence filters={filters} />
        </section>

        <section className="dashboard-grid">
          <Panel

            title="Highest Risk Attackers"

            subtitle="Risk-ranked IP addresses"

          >

            <div className="risk-list">

              {attackers.length > 0 ? (

                attackers.slice(0, 5).map((attacker) => (

                  <div

                    className="risk-row"

                    key={attacker.src_ip}

                  >

                    <div className="risk-ip">

                      <strong>{attacker.src_ip}</strong>

                      <span>

                        {attacker.sessions.toLocaleString()} sessions

                      </span>

                    </div>

                    <RiskBadge level={attacker.risk_level} />

                    <strong className="risk-score">

                      {Number(attacker.risk_score).toFixed(1)}

                    </strong>

                  </div>

                ))

              ) : (

                <EmptyState text="No risk data for this filter." />

              )}

            </div>

          </Panel>

        </section>

        <footer className="dashboard-footer">

          <div>Honeypot Attack Analytics</div>

          <div>FastAPI + React</div>

        </footer>

      </main>

    </div>

  );

}

/* =========================================================

   SIDEBAR

   ========================================================= */

function Sidebar() {

  const [activeSection, setActiveSection] = useState("overview");

  useEffect(() => {

    const sections = [

      "overview",

      "threat-intelligence",

      "credentials",

      "attack-sources",

    ];

    const observers = sections.map((sectionId) => {

      const element = document.getElementById(sectionId);

      if (!element) {

        return null;

      }

      const observer = new IntersectionObserver(

        (entries) => {

          const visible = entries.find(

            (entry) => entry.isIntersecting

          );

          if (visible) {

            setActiveSection(visible.target.id);

          }

        },

        {

          rootMargin: "-20% 0px -65% 0px",

          threshold: 0,

        }

      );

      observer.observe(element);

      return observer;

    });

    return () => {

      observers.forEach((observer) => {

        observer?.disconnect();

      });

    };

  }, []);

  return (

    <aside className="sidebar">

      <div className="brand">

        <div className="brand-icon">

          <Shield />

        </div>

        <div>

          <div className="brand-title">Honeypot</div>

          <div className="brand-subtitle">

            Attack Analytics

          </div>

        </div>

      </div>

      <nav className="sidebar-nav">

        <SidebarItem

          icon={<Activity />}

          label="Overview"

          href="#overview"

          active={activeSection === "overview"}

        />

        <SidebarItem

          icon={<ShieldAlert />}

          label="Threat Intelligence"

          href="#threat-intelligence"

          active={activeSection === "threat-intelligence"}

        />

        <SidebarItem

          icon={<KeyRound />}

          label="Credentials"

          href="#credentials"

          active={activeSection === "credentials"}

        />

        <SidebarItem

          icon={<Globe />}

          label="Attack Sources"

          href="#attack-sources"

          active={activeSection === "attack-sources"}

        />

      </nav>

      <div className="system-status">

        <div className="status-dot" />

        <div>

          <strong>System Online</strong>

          <span>FastAPI connected</span>

        </div>

      </div>

    </aside>

  );

}

function SidebarItem({ icon, label, active, href }) {

  return (

    <a

      className={`sidebar-item ${active ? "active" : ""}`}

      href={href}

    >

      {icon}

      <span>{label}</span>

    </a>

  );

}

function SourceIntelligence({ filters }) {
  const [country, setCountry] = useState("");
  const [riskLevel, setRiskLevel] = useState("");
  const [sortBy, setSortBy] = useState("total_events");
  const [sortOrder, setSortOrder] = useState("desc");
  const [page, setPage] = useState(0);
  const [selectedAttacker, setSelectedAttacker] = useState("");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const pageSize = 25;

  useEffect(() => {
    let active = true;
    async function loadSources() {
      try {
        setLoading(true);
        setError("");
        const params = {
          limit: pageSize,
          offset: page * pageSize,
          sort_by: sortBy,
          sort_order: sortOrder,
          ...filters,
        };
        if (!params.start) delete params.start;
        if (!params.end) delete params.end;
        if (!params.behavior) delete params.behavior;
        if (country) params.country = country;
        if (riskLevel) params.risk_level = riskLevel;
        const response = await axios.get(`${API}/api/source-intelligence`, { params });
        if (!Array.isArray(response.data?.sources) || !Array.isArray(response.data?.map_points)) {
          throw new Error("Unexpected source intelligence response");
        }
        if (active) setData(response.data);
      } catch (err) {
        console.error("Failed to load source intelligence:", err);
        if (active) {
          setData(null);
          setError(err.response?.data?.detail || "Unable to load attack source data.");
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    loadSources();
    return () => { active = false; };
  }, [filters, country, riskLevel, sortBy, sortOrder, page]);

  const overview = data?.overview || {};
  const toggleSort = (key) => {
    if (sortBy === key) setSortOrder((current) => current === "asc" ? "desc" : "asc");
    else { setSortBy(key); setSortOrder(key === "src_ip" || key === "country" || key === "city" ? "asc" : "desc"); }
    setPage(0);
  };
  const sortButton = (label, key) => (
    <button type="button" className="source-sort" onClick={() => toggleSort(key)}>
      {label}{sortBy === key ? (sortOrder === "asc" ? " ↑" : " ↓") : ""}
    </button>
  );

  return (
    <div className="source-intelligence">
      <div className="source-overview-grid">
        {[
          ["Unique source IPs", overview.unique_source_ips],
          ["Attack events", overview.total_attack_events],
          ["Countries represented", overview.countries_represented],
          ["High-risk sources", overview.high_risk_sources],
        ].map(([label, value]) => (
          <div className="source-overview-card" key={label}>
            <span>{label}</span><strong>{loading && !data ? "—" : Number(value || 0).toLocaleString()}</strong>
          </div>
        ))}
      </div>

      <div className="source-filter-bar">
        <label>Country
          <select value={country} onChange={(event) => { setCountry(event.target.value); setPage(0); }}>
            <option value="">All countries</option>
            {(data?.countries || []).map((row) => <option key={row.country} value={row.country}>{row.country}</option>)}
          </select>
        </label>
        <label>Risk level
          <select value={riskLevel} onChange={(event) => { setRiskLevel(event.target.value); setPage(0); }}>
            <option value="">All risk levels</option>
            {["High", "Medium", "Low", "Unknown"].map((level) => <option key={level}>{level}</option>)}
          </select>
        </label>
        {(country || riskLevel) && <button type="button" onClick={() => { setCountry(""); setRiskLevel(""); setPage(0); }}>Clear source filters</button>}
        {loading && <span className="source-loading">Updating source data…</span>}
      </div>

      {error && <div className="error-banner"><AlertTriangle size={18} /><span>{error}</span></div>}
      {!error && data && (
        <>
          <div className="source-content-grid">
            <Panel title="Country Analysis" subtitle="Event counts use the active date, behavior, country, and risk filters.">
              {data.countries.length ? (
                <div className="table-wrapper"><table className="source-table">
                  <thead><tr><th>COUNTRY</th><th>SOURCE IPS</th><th>EVENTS</th><th>FAILED LOGINS</th><th>HIGH RISK</th></tr></thead>
                  <tbody>{data.countries.map((row) => (
                    <tr key={row.country} className={country === row.country ? "source-row-selected" : ""}>
                      <td><button className="source-country-button" type="button" onClick={() => { setCountry(country === row.country ? "" : row.country); setPage(0); }}><Globe size={14} />{row.country}</button></td>
                      <td>{row.unique_ips.toLocaleString()}</td><td>{row.total_events.toLocaleString()}</td>
                      <td>{row.failed_logins.toLocaleString()}</td><td>{row.high_risk_sources.toLocaleString()}</td>
                    </tr>
                  ))}</tbody>
                </table></div>
              ) : <EmptyState text="No source or country data for these filters." />}
            </Panel>

            <Panel title="Top Attack Sources" subtitle="Sort columns to rank the filtered sources.">
              {data.sources.length ? <>
                <div className="table-wrapper"><table className="source-table">
                  <thead><tr>
                    <th>{sortButton("IP ADDRESS", "src_ip")}</th><th>{sortButton("COUNTRY / CITY", "country")}</th>
                    <th>{sortButton("EVENTS", "total_events")}</th><th>{sortButton("FAILED", "failed_logins")}</th>
                    <th>{sortButton("SUCCESSFUL HONEYPOT SESSIONS", "successful_sessions")}</th>
                    <th>{sortButton("RISK", "risk_score")}</th><th>{sortButton("LAST SEEN", "last_seen")}</th>
                  </tr></thead>
                  <tbody>{data.sources.map((row) => <tr key={row.src_ip}>
                    <td><button className="source-ip-button" type="button" onClick={() => setSelectedAttacker(row.src_ip)}>{row.src_ip}</button></td>
                    <td>{row.country}{row.city ? ` / ${row.city}` : ""}</td>
                    <td>{Number(row.total_events || 0).toLocaleString()}</td><td>{Number(row.failed_logins || 0).toLocaleString()}</td>
                    <td>{Number(row.successful_sessions || 0).toLocaleString()}</td>
                    <td>{row.risk_score == null ? <RiskBadge level="Unknown" /> : <><strong>{Number(row.risk_score).toFixed(1)}</strong> <RiskBadge level={row.risk_level} /></>}</td>
                    <td>{row.last_seen || "—"}</td>
                  </tr>)}</tbody>
                </table></div>
                <div className="source-pagination"><span>{data.total_sources.toLocaleString()} sources · page {page + 1}</span>
                  <button type="button" disabled={page === 0 || loading} onClick={() => setPage((current) => Math.max(0, current - 1))}>Previous</button>
                  <button type="button" disabled={!data.has_more || loading} onClick={() => setPage((current) => current + 1)}>Next</button>
                </div>
              </> : <EmptyState text="No source IPs match these filters." />}
            </Panel>
          </div>

          <Panel title="Attacker Origin Map" subtitle="GeoIP locations are approximate; sources without recorded coordinates are omitted.">
            <AttackerMap data={data.map_points} filters={filters} selectedAttacker={selectedAttacker} />
          </Panel>
        </>
      )}
    </div>
  );
}

/* =========================================================

   MAP

   ========================================================= */

function FocusMarker({

  point,

  sessions,

  failed,

  selected,

  onSelect,

}) {

  const map = useMap();

  const latitude = Number(point.latitude);

  const longitude = Number(point.longitude);

  const baseRadius = Math.max(

    5,

    Math.min(15, 5 + Math.sqrt(sessions) * 1.05)

  );

  const radius = selected

    ? Math.min(baseRadius + 4, 19)

    : baseRadius;

  const riskLevel = String(point.risk_level || "Unknown");

  const riskColors = {

    High: {

      color: "#ef4444",

      glow: "#f87171",

    },

    Medium: {

      color: "#f59e0b",

      glow: "#fbbf24",

    },

    Low: {

      color: "#22c55e",

      glow: "#4ade80",

    },

    Unknown: {

      color: "#64748b",

      glow: "#94a3b8",

    },

  };

  const riskColor = riskColors[riskLevel] || riskColors.Low;

  const handleClick = () => {

    onSelect(point.src_ip);

    map.flyTo(

      [latitude, longitude],

      Math.max(map.getZoom(), 4),

      {

        duration: 0.8,

      }

    );

  };

  return (

    <CircleMarker

      center={[latitude, longitude]}

      radius={radius}

      eventHandlers={{

        click: handleClick,

      }}

      pathOptions={{

        color: selected ? "#ffffff" : riskColor.glow,

        fillColor: riskColor.color,

        fillOpacity: selected ? 0.95 : 0.78,

        weight: selected ? 3 : 1.5,

      }}

    >

      <Popup>

        <div className="map-popup">

          <div className="map-popup-header">

            <div className="map-popup-ip">

              {point.src_ip}

            </div>

            <span

              className="map-popup-risk"

              style={{

                borderColor: riskColor.color,

                color: riskColor.color,

              }}

            >

              {riskLevel}

            </span>

          </div>

          <div className="map-popup-location">

            {point.city && point.country

              ? `${point.city}, ${point.country}`

              : point.country || "Unknown location"}

          </div>

          <div className="map-popup-divider" />

          <div className="map-popup-stat-grid">

            <div>

              <span>ATTACK EVENTS</span>

              <strong>{Number(point.total_events ?? sessions).toLocaleString()}</strong>

            </div>

            <div>

              <span>FAILED LOGINS</span>

              <strong>{failed.toLocaleString()}</strong>

            </div>

          </div>

          <div className="map-popup-note">

            Approximate IP geolocation

          </div>

        </div>

      </Popup>

    </CircleMarker>

  );

}

function ThreatHunt({ filters, onSelectAttacker }) {
  const [draft, setDraft] = useState({
    src_ip: "", username: "", command: "", event_type: "", risk_level: "",
  });
  const [search, setSearch] = useState({});
  const [page, setPage] = useState(0);
  const [results, setResults] = useState({ items: [], total: 0, limit: 50, has_more: false });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    async function runSearch() {
      try {
        setLoading(true);
        setError("");
        const params = { limit: 50, offset: page * 50 };
        if (filters.start) params.start = filters.start;
        if (filters.end) params.end = filters.end;
        if (filters.behavior) params.behavior = filters.behavior;
        Object.entries(search).forEach(([key, value]) => {
          if (value) params[key] = value;
        });
        const response = await axios.get(`${API}/api/threat-hunt`, { params });
        if (!Array.isArray(response.data?.items)) throw new Error("Unexpected threat hunt response");
        if (active) setResults(response.data);
      } catch (err) {
        console.error("Failed to search honeypot events:", err);
        if (active) {
          setResults({ items: [], total: 0, limit: 50, has_more: false });
          setError(err.response?.data?.detail || "Unable to search recorded events.");
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    runSearch();
    return () => { active = false; };
  }, [filters, search, page]);

  const updateDraft = (field, value) => {
    setDraft((current) => ({ ...current, [field]: value }));
  };

  const submitSearch = (event) => {
    event.preventDefault();
    const criteria = Object.fromEntries(
      Object.entries(draft).map(([key, value]) => [key, value.trim()])
        .filter(([, value]) => value)
    );
    setPage(0);
    setSearch(criteria);
  };

  const exportCsv = async () => {
    try {
      const params = {};
      if (filters.start) params.start = filters.start;
      if (filters.end) params.end = filters.end;
      if (filters.behavior) params.behavior = filters.behavior;
      Object.entries(search).forEach(([key, value]) => { params[key] = value; });
      const response = await axios.get(`${API}/api/threat-hunt/export`, {
        params, responseType: "blob",
      });
      const url = URL.createObjectURL(response.data);
      const link = document.createElement("a");
      link.href = url;
      link.download = "threat-hunt-results.csv";
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (err) {
      console.error("Failed to export threat hunt results:", err);
      setError("Unable to export matching investigation results.");
    }
  };

  const startLabel = filters.start || "All dates";
  const endLabel = filters.end || "Latest";
  const behaviorLabel = filters.behavior || "All behaviors";

  return (
    <section className="attacker-profile-panel threat-hunt-panel">
      <div className="threat-hunt-heading">
        <div>
          <div className="attacker-profile-kicker">THREAT HUNTING WORKSPACE</div>
          <p>Search stored event records. Date and behavior scope follows the dashboard filters.</p>
        </div>
        <button type="button" className="threat-hunt-export" onClick={exportCsv} disabled={!results.total}>
          Export matching CSV
        </button>
      </div>
      <div className="threat-hunt-scope">
        <span>Date: {startLabel} – {endLabel}</span>
        <span>Behavior: {behaviorLabel}</span>
      </div>
      <form className="threat-hunt-filters" onSubmit={submitSearch}>
        <label>Source IP<input value={draft.src_ip} onChange={(event) => updateDraft("src_ip", event.target.value)} placeholder="Exact IP" /></label>
        <label>Username<input value={draft.username} onChange={(event) => updateDraft("username", event.target.value)} placeholder="Contains…" /></label>
        <label>Command text<input value={draft.command} onChange={(event) => updateDraft("command", event.target.value)} placeholder="Contains…" /></label>
        <label>Event type
          <select value={draft.event_type} onChange={(event) => updateDraft("event_type", event.target.value)}>
            <option value="">All event types</option>
            <option value="cowrie.session.connect">Session connected</option>
            <option value="cowrie.login.failed">Failed login</option>
            <option value="cowrie.login.success">Successful honeypot login</option>
            <option value="cowrie.command.input">Command observed</option>
            <option value="cowrie.session.closed">Session closed</option>
          </select>
        </label>
        <label>Risk level
          <select value={draft.risk_level} onChange={(event) => updateDraft("risk_level", event.target.value)}>
            <option value="">All levels</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </label>
        <button type="submit" className="filter-button">Search</button>
      </form>
      <div className="threat-hunt-results-heading">
        <span>{loading ? "Searching…" : `${results.total.toLocaleString()} matching events`}</span>
        <span>Page size: {results.limit}</span>
      </div>
      {error ? <div className="attacker-profile-error">{error}</div> : null}
      {!loading && !error && !results.items.length ? (
        <div className="attacker-profile-empty">No recorded events match all selected criteria.</div>
      ) : null}
      {results.items.length > 0 && (
        <>
          <div className="threat-hunt-table-wrap">
            <table className="threat-hunt-table">
              <thead>
                <tr><th>Timestamp</th><th>Source IP</th><th>Event type</th><th>Session</th><th>Username</th><th>Command</th><th>Risk</th></tr>
              </thead>
              <tbody>
                {results.items.map((item, index) => (
                  <tr key={`${item.timestamp}-${item.session_id}-${index}`}>
                    <td>{item.timestamp || "—"}</td>
                    <td>
                      {item.src_ip ? (
                        <button type="button" className="threat-hunt-ip" onClick={() => onSelectAttacker(item.src_ip)}>
                          {item.src_ip}
                        </button>
                      ) : "—"}
                    </td>
                    <td>{item.event_type || "—"}</td>
                    <td>{item.session_id || "—"}</td>
                    <td>{item.username || "—"}</td>
                    <td className="threat-hunt-command" title={item.command || ""}>{item.command || "—"}</td>
                    <td>{item.risk_level ? <><RiskBadge level={item.risk_level} /> <small>{item.risk_score}</small></> : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="threat-hunt-pagination">
            <button type="button" onClick={() => setPage((current) => Math.max(0, current - 1))} disabled={page === 0 || loading}>Previous</button>
            <span>Page {page + 1} of {Math.max(1, Math.ceil(results.total / results.limit))}</span>
            <button type="button" onClick={() => setPage((current) => current + 1)} disabled={!results.has_more || loading}>Next</button>
          </div>
        </>
      )}
    </section>
  );
}

function ThreatAlerts({ filters, onSelectAttacker }) {
  const [draft, setDraft] = useState({ severity: "", rule_id: "", source_ip: "" });
  const [criteria, setCriteria] = useState({});
  const [page, setPage] = useState(0);
  const [results, setResults] = useState({ items: [], total: 0, limit: 25, rule_catalog: [] });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState("");

  useEffect(() => {
    let active = true;
    async function loadAlerts() {
      try {
        setLoading(true);
        setError("");
        const params = { limit: 25, offset: page * 25 };
        if (filters.start) params.start = filters.start;
        if (filters.end) params.end = filters.end;
        if (filters.behavior) params.behavior = filters.behavior;
        Object.entries(criteria).forEach(([key, value]) => { if (value) params[key] = value; });
        const response = await axios.get(`${API}/api/alerts`, { params });
        if (!Array.isArray(response.data?.items)) throw new Error("Unexpected alert response");
        if (active) setResults(response.data);
      } catch (err) {
        console.error("Failed to load threat alerts:", err);
        if (active) {
          setResults({ items: [], total: 0, limit: 25, rule_catalog: [] });
          setError(err.response?.data?.detail || "Unable to load threat alerts.");
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    loadAlerts();
    return () => { active = false; };
  }, [filters, criteria, page]);

  useEffect(() => {
    if (!selectedAlertId) {
      setSelectedAlert(null);
      return undefined;
    }
    let active = true;
    async function loadDetail() {
      try {
        setDetailLoading(true);
        setDetailError("");
        const params = {};
        if (filters.start) params.start = filters.start;
        if (filters.end) params.end = filters.end;
        if (filters.behavior) params.behavior = filters.behavior;
        const response = await axios.get(
          `${API}/api/alerts/${encodeURIComponent(selectedAlertId)}`, { params }
        );
        if (active) setSelectedAlert(response.data);
      } catch (err) {
        console.error("Failed to load alert details:", err);
        if (active) {
          setSelectedAlert(null);
          setDetailError("This alert is unavailable for the current date and behavior filters.");
        }
      } finally {
        if (active) setDetailLoading(false);
      }
    }
    loadDetail();
    return () => { active = false; };
  }, [selectedAlertId, filters]);

  const applyFilters = (event) => {
    event.preventDefault();
    setCriteria(Object.fromEntries(
      Object.entries(draft).map(([key, value]) => [key, value.trim()])
        .filter(([, value]) => value)
    ));
    setPage(0);
  };

  const updateDraft = (key, value) => setDraft((current) => ({ ...current, [key]: value }));

  return (
    <section className="attacker-profile-panel threat-alerts-panel">
      <div className="threat-hunt-heading">
        <div>
          <div className="attacker-profile-kicker">AUTOMATED THREAT ALERTS</div>
          <p>Aggregated recorded events, grouped by source IP, session, and rule. Severity is triage priority, not attribution.</p>
        </div>
      </div>
      <div className="threat-hunt-scope">
        <span>Date: {filters.start || "All dates"} – {filters.end || "Latest"}</span>
        <span>Behavior: {filters.behavior || "All behaviors"}</span>
        <span>Severity rules: 5–9 failed logins = Medium; 10+ = High; successful honeypot login = High; download-tool activity = Medium.</span>
      </div>
      <details className="threat-alert-rule-catalog">
        <summary>Detection and severity criteria</summary>
        <ul>
          {results.rule_catalog.map((rule) => (
            <li key={rule.rule_id}>
              <strong>{rule.rule_name}:</strong> {rule.criteria} <span>{rule.severity}</span>
            </li>
          ))}
        </ul>
      </details>
      <form className="threat-alert-filters" onSubmit={applyFilters}>
        <label>Severity
          <select value={draft.severity} onChange={(event) => updateDraft("severity", event.target.value)}>
            <option value="">All severities</option><option value="High">High</option><option value="Medium">Medium</option>
          </select>
        </label>
        <label>Rule
          <select value={draft.rule_id} onChange={(event) => updateDraft("rule_id", event.target.value)}>
            <option value="">All rules</option>
            {results.rule_catalog.map((rule) => <option value={rule.rule_id} key={rule.rule_id}>{rule.rule_name}</option>)}
          </select>
        </label>
        <label>Source IP<input value={draft.source_ip} onChange={(event) => updateDraft("source_ip", event.target.value)} placeholder="Exact IP" /></label>
        <button type="submit" className="filter-button">Filter alerts</button>
      </form>
      <div className="threat-hunt-results-heading">
        <span>{loading ? "Loading alerts…" : `${results.total.toLocaleString()} alerts`}</span>
      </div>
      {error && <div className="attacker-profile-error">{error}</div>}
      {!loading && !error && !results.items.length && (
        <div className="attacker-profile-empty">No alerts match the current date, behavior, and alert filters.</div>
      )}
      <div className="threat-alert-list">
        {results.items.map((alert) => (
          <article className="threat-alert-card" key={alert.alert_id}>
            <div className="threat-alert-card-main">
              <RiskBadge level={alert.severity} />
              <strong>{alert.rule_name}</strong>
              <button type="button" className="threat-hunt-ip" onClick={() => onSelectAttacker(alert.source_ip)}>
                {alert.source_ip}
              </button>
              <span>{alert.first_seen || "Timestamp unavailable"}</span>
              <span>{alert.event_count} supporting event(s)</span>
            </div>
            <button
              type="button"
              className="threat-alert-detail-button"
              onClick={() => setSelectedAlertId(
                selectedAlertId === alert.alert_id ? null : alert.alert_id
              )}
            >
              {selectedAlertId === alert.alert_id ? "Close details" : "Inspect alert"}
            </button>
          </article>
        ))}
      </div>
      {results.items.length > 0 && (
        <div className="threat-hunt-pagination">
          <button type="button" onClick={() => setPage((current) => Math.max(0, current - 1))} disabled={page === 0 || loading}>Previous</button>
          <span>Page {page + 1} of {Math.max(1, Math.ceil(results.total / results.limit))}</span>
          <button type="button" onClick={() => setPage((current) => current + 1)} disabled={!results.has_more || loading}>Next</button>
        </div>
      )}
      {selectedAlertId && (detailLoading ? (
        <div className="attacker-profile-loading">Loading alert evidence…</div>
      ) : detailError ? (
        <div className="attacker-profile-error">{detailError}</div>
      ) : selectedAlert ? (
        <div className="threat-alert-detail">
          <div className="threat-alert-detail-heading">
            <RiskBadge level={selectedAlert.severity} />
            <strong>{selectedAlert.rule_name}</strong>
            <span>{selectedAlert.first_seen} – {selectedAlert.last_seen}</span>
          </div>
          <button type="button" className="threat-hunt-ip" onClick={() => onSelectAttacker(selectedAlert.source_ip)}>
            Open attacker profile: {selectedAlert.source_ip}
          </button>
          <p>{selectedAlert.severity_rationale}</p>
          <div className="threat-alert-detail-meta">
            <span>Sessions: {selectedAlert.session_ids.join(", ") || "Unavailable"}</span>
            <span>Supporting event counts: {Object.entries(selectedAlert.supporting_event_counts).map(([type, count]) => `${type}: ${count}`).join(" · ")}</span>
          </div>
          <div className="threat-alert-evidence">
            {Object.entries(selectedAlert.evidence).map(([key, value]) => (
              <div key={key}>
                <strong>{key.replaceAll("_", " ")}</strong>
                {Array.isArray(value) ? value.map((item, index) => (
                  <code key={index}>{typeof item === "object" ? `${item.pattern}: ${item.commands.join("; ")}` : String(item)}</code>
                )) : <code>{String(value)}</code>}
              </div>
            ))}
          </div>
          <p className="threat-alert-note">{selectedAlert.assessment_note}</p>
        </div>
      ) : null)}
    </section>
  );
}

function AttackerMap({ data, filters, selectedAttacker = "" }) {

  const [selectedIp, setSelectedIp] = useState(null);

  const [tileUnavailable, setTileUnavailable] = useState(false);

  const [profile, setProfile] = useState(null);

  const [profileLoading, setProfileLoading] = useState(false);

  const [profileError, setProfileError] = useState("");

  const [dna, setDna] = useState(null);

  const [dnaLoading, setDnaLoading] = useState(false);

  const [dnaError, setDnaError] = useState("");

  const [similarAttackers, setSimilarAttackers] = useState([]);

  const [similarLoading, setSimilarLoading] = useState(false);

  const [similarError, setSimilarError] = useState("");

  const [intent, setIntent] = useState(null);

  const [intentLoading, setIntentLoading] = useState(false);

  const [intentError, setIntentError] = useState("");

  const [attackerTimeline, setAttackerTimeline] = useState(null);

  const [timelineLoading, setTimelineLoading] = useState(false);

  const [timelineError, setTimelineError] = useState("");

  const [timelineEventType, setTimelineEventType] = useState("all");

  const [campaigns, setCampaigns] = useState([]);

  const [campaignsLoading, setCampaignsLoading] = useState(false);

  const [campaignsError, setCampaignsError] = useState("");

  const [selectedCampaignId, setSelectedCampaignId] = useState(null);

  const [campaignDetail, setCampaignDetail] = useState(null);

  const [campaignDetailError, setCampaignDetailError] = useState("");

  const preserveUnmappedSelection = useRef(false);

  useEffect(() => {
    if (!selectedAttacker) return;
    preserveUnmappedSelection.current = !data.some((point) => point.src_ip === selectedAttacker);
    setSelectedIp(selectedAttacker);
  }, [selectedAttacker, data]);

  useEffect(() => {
    async function loadCampaigns() {
      try {
        setCampaignsLoading(true);
        setCampaignsError("");
        const params = {};
        if (filters.start) params.start = filters.start;
        if (filters.end) params.end = filters.end;
        if (filters.behavior) params.behavior = filters.behavior;
        const response = await axios.get(`${API}/api/campaigns`, { params });
        if (!Array.isArray(response.data)) throw new Error("Unexpected campaign response");
        setCampaigns(response.data);
      } catch (err) {
        console.error("Failed to load candidate campaigns:", err);
        setCampaigns([]);
        setCampaignsError("Unable to load candidate campaigns.");
      } finally {
        setCampaignsLoading(false);
      }
    }
    loadCampaigns();
  }, [filters]);

  useEffect(() => {
    if (!selectedCampaignId) {
      setCampaignDetail(null);
      return;
    }
    async function loadCampaignDetail() {
      try {
        setCampaignDetailError("");
        const params = {};
        if (filters.start) params.start = filters.start;
        if (filters.end) params.end = filters.end;
        if (filters.behavior) params.behavior = filters.behavior;
        const response = await axios.get(
          `${API}/api/campaigns/${encodeURIComponent(selectedCampaignId)}`, { params }
        );
        setCampaignDetail(response.data);
      } catch (err) {
        console.error("Failed to load candidate campaign:", err);
        setCampaignDetail(null);
        setCampaignDetailError("This candidate campaign is unavailable for the current filters.");
      }
    }
    loadCampaignDetail();
  }, [selectedCampaignId, filters]);

  useEffect(() => {

    if (!selectedIp) {

      return;

    }

    const attackerStillVisible = data.some(

      (point) => point.src_ip === selectedIp

    );

    if (!attackerStillVisible) {

      if (preserveUnmappedSelection.current) {

        preserveUnmappedSelection.current = false;

        return;

      }

      setSelectedIp(null);

      setProfile(null);

      setProfileError("");

      setProfileLoading(false);

      setDna(null);

      setDnaError("");

      setDnaLoading(false);

    }

  }, [data, selectedIp]);

  useEffect(() => {

    if (!selectedIp) {

      setProfile(null);

      setProfileError("");

      return;

    }

    async function loadProfile() {

      try {

        setProfileLoading(true);

        setProfileError("");

        const params = {};

        if (filters.start) params.start = filters.start;

        if (filters.end) params.end = filters.end;

        if (filters.behavior) params.behavior = filters.behavior;

        const response = await axios.get(

          `${API}/api/attackers/${encodeURIComponent(selectedIp)}`,

          { params }

        );

        setProfile(response.data);

      } catch (err) {

        console.error("Failed to load attacker profile:", err);

        setProfile(null);

        setProfileError("Unable to load attacker profile.");

      } finally {

        setProfileLoading(false);

      }

    }

    loadProfile();

  }, [selectedIp, filters]);

  useEffect(() => {

    if (!selectedIp) {

      setDna(null);

      setDnaError("");

      return;

    }

    async function loadDna() {

      try {

        setDnaLoading(true);

        setDnaError("");

        const params = {};

        if (filters.start) params.start = filters.start;

        if (filters.end) params.end = filters.end;

        if (filters.behavior) params.behavior = filters.behavior;

        const response = await axios.get(

          `${API}/api/attackers/${encodeURIComponent(

            selectedIp

          )}/dna`,

          { params }

        );

        setDna(response.data);

      } catch (err) {

        console.error("Failed to load attacker DNA:", err);

        setDna(null);

        setDnaError("Unable to load attacker DNA.");

      } finally {

        setDnaLoading(false);

      }

    }

    loadDna();

  }, [selectedIp, filters]);

  useEffect(() => {

    if (!selectedIp) {

      setSimilarAttackers([]);

      setSimilarError("");

      return;

    }

    async function loadSimilarAttackers() {

      try {

        setSimilarLoading(true);

        setSimilarError("");

        const params = {};

        if (filters.start) params.start = filters.start;

        if (filters.end) params.end = filters.end;

        if (filters.behavior) params.behavior = filters.behavior;

        const response = await axios.get(

          `${API}/api/attackers/${encodeURIComponent(selectedIp)}/similar`,

          { params }

        );

        if (!Array.isArray(response.data)) {

          throw new Error("Unexpected similarity response format");

        }

        setSimilarAttackers(response.data);

      } catch (err) {

        console.error("Failed to load similar attackers:", err);

        setSimilarAttackers([]);

        const detail = err.response?.data?.detail;
        if (err.response?.status === 404 && detail === "Not Found") {
          setSimilarError(
            "The API server is outdated. Stop it and restart run_api.py from D:\\Desktop\\honeypot-attack-analytics-main."
          );
        } else {
          setSimilarError("Unable to load similar attackers.");
        }

      } finally {

        setSimilarLoading(false);

      }

    }

    loadSimilarAttackers();

  }, [selectedIp, filters]);

  useEffect(() => {
    if (!selectedIp) {
      setIntent(null);
      setIntentError("");
      return;
    }

    async function loadIntent() {
      try {
        setIntentLoading(true);
        setIntentError("");
        const params = {};
        if (filters.start) params.start = filters.start;
        if (filters.end) params.end = filters.end;
        if (filters.behavior) params.behavior = filters.behavior;

        const response = await axios.get(
          `${API}/api/attackers/${encodeURIComponent(selectedIp)}/intent`,
          { params }
        );
        setIntent(response.data);
      } catch (err) {
        console.error("Failed to load attack intent:", err);
        setIntent(null);
        setIntentError("Unable to load inferred attack intent.");
      } finally {
        setIntentLoading(false);
      }
    }

    loadIntent();
  }, [selectedIp, filters]);

  useEffect(() => {
    if (!selectedIp) {
      setAttackerTimeline(null);
      setTimelineError("");
      return;
    }
    let active = true;
    async function loadTimeline() {
      try {
        setTimelineLoading(true);
        setTimelineError("");
        const params = {};
        if (filters.start) params.start = filters.start;
        if (filters.end) params.end = filters.end;
        if (filters.behavior) params.behavior = filters.behavior;
        if (timelineEventType !== "all") params.event_type = timelineEventType;
        const response = await axios.get(
          `${API}/api/attackers/${encodeURIComponent(selectedIp)}/timeline`,
          { params }
        );
        if (!Array.isArray(response.data?.events)) {
          throw new Error("Unexpected attacker timeline response");
        }
        if (active) setAttackerTimeline(response.data);
      } catch (err) {
        console.error("Failed to load attacker timeline:", err);
        if (active) {
          setAttackerTimeline(null);
          setTimelineError("Unable to load the filtered event timeline.");
        }
      } finally {
        if (active) setTimelineLoading(false);
      }
    }
    loadTimeline();
    return () => {
      active = false;
    };
  }, [selectedIp, filters, timelineEventType]);

  return (

    <div className="attacker-map">

      {data.length ? <MapContainer

        center={[20, 0]}

        zoom={2}

        minZoom={2}

        maxZoom={7}

        scrollWheelZoom={true}

        worldCopyJump={true}

        className="attacker-map-container"

      >

        <TileLayer
          attribution="&copy; OpenStreetMap contributors"
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          eventHandlers={{
            tileerror: () => setTileUnavailable(true),
            tileload: () => setTileUnavailable(false),
          }}
        />

        {data.map((point) => {

          const sessions = Number(point.total_events ?? point.sessions ?? 0);

          const failed = Number(point.failed_logins || 0);

          return (

            <FocusMarker

              key={point.src_ip}

              point={point}

              sessions={sessions}

              failed={failed}

              selected={selectedIp === point.src_ip}

              onSelect={setSelectedIp}

            />

          );

        })}

      </MapContainer> : <EmptyState text="No geolocation data for this filter." />}

      {data.length > 0 && tileUnavailable && (
        <div className="map-basemap-warning">
          Map tiles could not load. Check your internet connection or tile-provider access.
        </div>
      )}

      {data.length > 0 && <div className="map-footer">

        <div className="map-legend">

          <span className="map-legend-title">RISK LEVEL</span>

          <span className="map-legend-item">

            <i className="map-legend-dot low" /> Low

          </span>

          <span className="map-legend-item">

            <i className="map-legend-dot medium" /> Medium

          </span>

          <span className="map-legend-item">

            <i className="map-legend-dot high" /> High

          </span>

        </div>

        <span className="map-count">

          {data.length} attacker IPs mapped

        </span>

      </div>}

      {data.length > 0 && <div className="map-disclaimer">

        IP geolocation is approximate and represents the registered

        geographic location of the source IP, not the exact physical

        location of an attacker.

      </div>}

      <ThreatAlerts
        filters={filters}
        onSelectAttacker={(ip) => {
          preserveUnmappedSelection.current = !data.some((point) => point.src_ip === ip);
          setSelectedIp(ip);
        }}
      />

      <ThreatHunt
        filters={filters}
        onSelectAttacker={(ip) => {
          preserveUnmappedSelection.current = !data.some((point) => point.src_ip === ip);
          setSelectedIp(ip);
        }}
      />

      <section className="attacker-profile-panel campaign-panel">
        <div className="attacker-profile-kicker">CANDIDATE ATTACK CAMPAIGNS</div>
        <p className="campaign-caveat">
          Shared honeypot behavior is evidence for correlation only; it does not prove common ownership,
          coordination, or attribution.
        </p>
        {campaignsLoading ? (
          <div className="attacker-profile-loading">Loading candidate campaigns…</div>
        ) : campaignsError ? (
          <div className="attacker-profile-error">{campaignsError}</div>
        ) : !campaigns.length ? (
          <div className="attacker-profile-empty">No candidate campaigns meet the evidence threshold for these filters.</div>
        ) : (
          <div className="campaign-list">
            {campaigns.map((campaign) => (
              <button
                type="button"
                className="attacker-similarity-row campaign-row"
                key={campaign.campaign_id}
                onClick={() => setSelectedCampaignId(
                  selectedCampaignId === campaign.campaign_id ? null : campaign.campaign_id
                )}
              >
                <span className="attacker-similarity-main">
                  <strong>{campaign.campaign_id}</strong>
                  <small>{campaign.attacker_count} attackers · {campaign.confidence_level} confidence</small>
                </span>
                <span>{campaign.first_seen ? new Date(campaign.first_seen).toLocaleDateString() : "Unknown"}</span>
              </button>
            ))}
          </div>
        )}
        {selectedCampaignId && (campaignDetailError ? (
          <div className="attacker-profile-error">{campaignDetailError}</div>
        ) : campaignDetail ? (
          <div className="campaign-detail">
            <div className="attacker-profile-list-title">
              {campaignDetail.label} · {campaignDetail.attacker_count} ATTACKERS · {campaignDetail.confidence_level} CONFIDENCE
            </div>
            <p>{campaignDetail.explanation}</p>
            <div className="campaign-evidence">
              {campaignDetail.evidence.map((item) => <div key={item}>{item}</div>)}
            </div>
            <div className="attacker-profile-list-title">MEMBER IPs</div>
            {campaignDetail.members.map((member) => (
              <button
                type="button"
                className="attacker-similarity-row campaign-member"
                key={member.src_ip}
                onClick={() => {
                  preserveUnmappedSelection.current = !data.some((point) => point.src_ip === member.src_ip);
                  setSelectedIp(member.src_ip);
                }}
              >
                <span>{member.src_ip}</span>
                <small>{member.sessions} sessions</small>
              </button>
            ))}
          </div>
        ) : <div className="attacker-profile-loading">Loading campaign details…</div>)}
      </section>

      {selectedIp && (

        <section className="attacker-profile-panel">

          {profileLoading ? (

            <div className="attacker-profile-loading">

              Loading attacker intelligence…

            </div>

          ) : profileError ? (

            <div className="attacker-profile-error">

              {profileError}

            </div>

          ) : profile ? (

            <>

              <div className="attacker-profile-header">

                <div>

                  <div className="attacker-profile-kicker">

                    ATTACKER INTELLIGENCE

                  </div>

                  <div className="attacker-profile-ip">

                    {profile.src_ip}

                  </div>

                  <div className="attacker-profile-location">

                    {profile.city

                      ? `${profile.city}, `

                      : ""}

                    {profile.country || "Unknown location"}

                  </div>

                </div>

                <div className="attacker-profile-risk-wrap">

                  <span

                    className={`attacker-profile-risk ${String(

                      profile.risk_level || ""

                    ).toLowerCase()}`}

                  >

                    {profile.risk_level || "Unknown"}

                  </span>

                  <button

                    className="attacker-profile-close"

                    onClick={() => setSelectedIp(null)}

                  >

                    Close

                  </button>

                </div>

              </div>

              <div className="attacker-profile-stats">

                <div className="attacker-profile-stat">

                  <span>RISK SCORE</span>

                  <strong>

                    {Number(profile.risk_score || 0).toFixed(1)} / 100

                  </strong>

                </div>

                <div className="attacker-profile-stat">

                  <span>SESSIONS</span>

                  <strong>

                    {Number(profile.sessions || 0).toLocaleString()}

                  </strong>

                </div>

                <div className="attacker-profile-stat">

                  <span>FAILED LOGINS</span>

                  <strong>

                    {Number(

                      profile.failed_logins || 0

                    ).toLocaleString()}

                  </strong>

                </div>

                <div className="attacker-profile-stat">

                  <span>SUCCESSFUL</span>

                  <strong>

                    {Number(

                      profile.successful_sessions || 0

                    ).toLocaleString()}

                  </strong>

                </div>

                <div className="attacker-profile-stat">

                  <span>COMMANDS</span>

                  <strong>

                    {Number(profile.commands || 0).toLocaleString()}

                  </strong>

                </div>

              </div>

              <div className="attacker-profile-meta">

                <div>

                  <span>FIRST SEEN</span>

                  <strong>{profile.first_seen || "—"}</strong>

                </div>

                <div>

                  <span>LAST SEEN</span>

                  <strong>{profile.last_seen || "—"}</strong>

                </div>

                <div>

                  <span>BEHAVIOR</span>

                  <strong>

                    {profile.behavior || "Unclustered"}

                  </strong>

                </div>

              </div>

              <div className="attacker-dna-panel">

                <div className="attacker-dna-header">

                  <div>

                    <div className="attacker-profile-kicker">

                      ATTACKER DNA

                    </div>

                    <div className="attacker-dna-title">

                      Behavioral Fingerprint

                    </div>

                  </div>

                  {dna?.fingerprint && (

                    <span className="attacker-dna-fingerprint">

                      {dna.fingerprint}

                    </span>

                  )}

                </div>

                {dnaLoading ? (

                  <div className="attacker-profile-loading">

                    Building behavioral fingerprint…

                  </div>

                ) : dnaError ? (

                  <div className="attacker-profile-error">

                    {dnaError}

                  </div>

                ) : dna ? (

                  <>

                    <div

                      className="attacker-dna-grid"

                      style={{

                        display: "grid",

                        gridTemplateColumns: "repeat(5, minmax(0, 1fr))",

                        gap: "8px",

                      }}

                    >

                      <DnaMetric

                        label="LOGIN RATE"

                        value={`${Number(

                          dna.login_rate || 0

                        ).toFixed(1)}%`}

                      />

                      <DnaMetric

                        label="COMMAND RATE"

                        value={`${Number(

                          dna.command_rate || 0

                        ).toFixed(1)}%`}

                      />

                      <DnaMetric

                        label="DOWNLOAD RATE"

                        value={`${Number(

                          dna.download_rate || 0

                        ).toFixed(1)}%`}

                      />

                      <DnaMetric

                        label="PERSISTENCE"

                        value={`${Number(

                          dna.persistence || 0

                        ).toFixed(1)}%`}

                      />

                      <DnaMetric

                        label="ACTIVITY"

                        value={`${Number(

                          dna.activity || 0

                        ).toFixed(1)}%`}

                      />

                    </div>

                  </>

                ) : (

                  <div className="attacker-profile-empty">

                    No behavioral DNA available.

                  </div>

                )}

              </div>

              <section className="attacker-intent-panel">
                <div className="attacker-profile-kicker">
                  INFERRED ATTACK INTENT
                </div>
                {intentLoading ? (
                  <div className="attacker-profile-loading">
                    Evaluating observed honeypot events…
                  </div>
                ) : intentError ? (
                  <div className="attacker-profile-error">{intentError}</div>
                ) : intent ? (
                  <>
                    <h3>{intent.classification}</h3>
                    <p>{intent.explanation}</p>
                    <div className="attacker-intent-evidence-title">
                      SUPPORTING EVIDENCE
                    </div>
                    <ul className="attacker-intent-evidence">
                      <li>{intent.evidence.sessions} observed session(s)</li>
                      {intent.evidence.failed_login_events > 0 && (
                        <li>
                          {intent.evidence.failed_login_events} failed login event(s) across {intent.evidence.sessions_with_failed_logins} session(s)
                        </li>
                      )}
                      {intent.evidence.successful_login_events > 0 && (
                        <li>
                          {intent.evidence.successful_login_events} successful login event(s) recorded by the honeypot
                        </li>
                      )}
                      {intent.evidence.command_count > 0 && (
                        <li>{intent.evidence.command_count} observed command(s)</li>
                      )}
                      {intent.evidence.commands_observed.map((command) => (
                        <li className="attacker-intent-command" key={command}>
                          <code>{command}</code>
                        </li>
                      ))}
                      {intent.evidence.download_tool_matches.length > 0 && (
                        <li>
                          Download tool match(es): {intent.evidence.download_tool_matches.join(", ")}
                        </li>
                      )}
                      {intent.evidence.connection_only_sessions > 0 && (
                        <li>
                          {intent.evidence.connection_only_sessions} connection-only session(s)
                        </li>
                      )}
                      {intent.evidence.recon_behavior_sessions > 0 && (
                        <li>
                          {intent.evidence.recon_behavior_sessions} session(s) with a scanner/recon behavior label
                        </li>
                      )}
                    </ul>
                    <p className="attacker-intent-caveat">
                      {intent.inference_note}
                    </p>
                  </>
                ) : null}
              </section>

              <section className="attacker-timeline-panel">
                <div className="attacker-timeline-header">
                  <div>
                    <div className="attacker-profile-kicker">ATTACK TIMELINE & INCIDENT</div>
                    <div className="attacker-timeline-caption">
                      Event timestamps retained to seconds; entries are observed honeypot records.
                    </div>
                  </div>
                  <label className="timeline-filter-label">
                    EVENT TYPE
                    <select
                      value={timelineEventType}
                      onChange={(event) => setTimelineEventType(event.target.value)}
                    >
                      <option value="all">All events</option>
                      {attackerTimeline?.available_event_types?.filter((eventType) => eventType !== "download_tool").map((eventType) => (
                        <option value={eventType} key={eventType}>{eventType}</option>
                      ))}
                      {attackerTimeline?.available_event_types?.includes("download_tool") && (
                        <option value="download_tool">Download-tool activity</option>
                      )}
                    </select>
                  </label>
                </div>
                {timelineLoading ? (
                  <div className="attacker-profile-loading">Loading filtered event history…</div>
                ) : timelineError ? (
                  <div className="attacker-profile-error">{timelineError}</div>
                ) : attackerTimeline ? (
                  <>
                    <div className="incident-summary">
                      <strong>INCIDENT SUMMARY</strong>
                      <p className="incident-summary-scope">
                        {attackerTimeline.incident_summary.scope}
                      </p>
                      <div className="incident-summary-stats">
                        <span><strong>{attackerTimeline.incident_summary.event_count}</strong> events</span>
                        <span><strong>{attackerTimeline.incident_summary.session_count}</strong> sessions</span>
                        <span>
                          <strong>Time range</strong>
                          {attackerTimeline.incident_summary.first_seen
                            ? `${attackerTimeline.incident_summary.first_seen} — ${attackerTimeline.incident_summary.last_seen}`
                            : "Unavailable"}
                        </span>
                      </div>
                      <div className="incident-event-counts">
                        {attackerTimeline.incident_summary.event_counts.map((item) => (
                          <span key={item.event_type}>
                            {item.event_type}<strong>{item.count}</strong>
                          </span>
                        ))}
                        {!attackerTimeline.incident_summary.event_counts.length && (
                          <span>No event types in this date/behavior scope.</span>
                        )}
                      </div>
                      <p className="incident-summary-description">
                        {attackerTimeline.incident_summary.description}
                      </p>
                    </div>
                    {attackerTimeline.events.length ? (
                      <ol className="attacker-timeline-list">
                        {attackerTimeline.events.map((item, index) => (
                          <li key={item.id ?? `${item.session}-${item.timestamp}-${index}`}>
                            <time>{item.timestamp || "Timestamp unavailable"}</time>
                            <div className="timeline-event-content">
                              <strong>{item.event_type}</strong>
                              {item.is_download_activity && <span className="timeline-download-tag">Download-tool match</span>}
                              {item.session && <small>Session {item.session}</small>}
                              {Object.entries(item.evidence || {}).map(([key, value]) => (
                                <div className="timeline-evidence" key={key}>
                                  <span>{key.replaceAll("_", " ")}</span>
                                  <code>{Array.isArray(value) ? value.join(", ") : String(value)}</code>
                                </div>
                              ))}
                            </div>
                          </li>
                        ))}
                      </ol>
                    ) : (
                      <div className="attacker-profile-empty">No events match this event-type filter.</div>
                    )}
                  </>
                ) : null}
              </section>

              <div className="attacker-similarity-panel">

                <div className="attacker-profile-kicker">Similar Attackers</div>

                {similarLoading ? (

                  <div className="attacker-profile-loading">

                    Comparing behavior for the current filters…

                  </div>

                ) : similarError ? (

                  <div className="attacker-profile-error">{similarError}</div>

                ) : similarAttackers.length ? (

                  similarAttackers.map((match) => (

                    <button

                      className="attacker-similarity-row"

                      key={match.src_ip}

                      type="button"

                      onClick={() => {

                        preserveUnmappedSelection.current = !data.some(

                          (point) => point.src_ip === match.src_ip

                        );

                        setSelectedIp(match.src_ip);

                      }}

                    >

                      <span className="attacker-similarity-main">

                        <strong>{match.src_ip}</strong>

                        <small>{(match.reasons || []).join(" · ")}</small>

                      </span>

                      <span className="attacker-similarity-score">

                        {match.similarity_pct}%

                      </span>

                      <span className={`attacker-profile-risk ${String(

                        match.risk_level || ""

                      ).toLowerCase()}`}>

                        {match.risk_level || "Unknown"}

                      </span>

                    </button>

                  ))

                ) : (

                  <div className="attacker-profile-empty">

                    No other attackers match the current filters.

                  </div>

                )}

              </div>

              <div className="attacker-profile-columns">

                <div className="attacker-profile-list">

                  <div className="attacker-profile-list-title">

                    TARGETED USERNAMES

                  </div>

                  {profile.usernames?.length ? (

                    profile.usernames.map((item) => (

                      <div

                        className="attacker-profile-list-row"

                        key={item.value}

                      >

                        <span>{item.value}</span>

                        <strong>{item.count}</strong>

                      </div>

                    ))

                  ) : (

                    <span className="attacker-profile-empty">

                      No usernames observed

                    </span>

                  )}

                </div>

                <div className="attacker-profile-list">

                  <div className="attacker-profile-list-title">

                    TARGETED PASSWORDS

                  </div>

                  {profile.passwords?.length ? (

                    profile.passwords.map((item) => (

                      <div

                        className="attacker-profile-list-row"

                        key={item.value}

                      >

                        <span>{item.value}</span>

                        <strong>{item.count}</strong>

                      </div>

                    ))

                  ) : (

                    <span className="attacker-profile-empty">

                      No passwords observed

                    </span>

                  )}

                </div>

                <div className="attacker-profile-list">

                  <div className="attacker-profile-list-title">

                    OBSERVED COMMANDS

                  </div>

                  {profile.commands_top?.length ? (

                    profile.commands_top.map((item) => (

                      <div

                        className="attacker-profile-list-row"

                        key={item.value}

                      >

                        <span title={item.value}>

                          {item.value}

                        </span>

                        <strong>{item.count}</strong>

                      </div>

                    ))

                  ) : (

                    <span className="attacker-profile-empty">

                      No commands observed

                    </span>

                  )}

                </div>

              </div>

            </>

          ) : null}

        </section>

      )}

    </div>

  );

}

function DnaMetric({ label, value }) {

  return (

    <div

      className="attacker-dna-metric"

      style={{

        minWidth: 0,

        padding: "10px",

        border: "1px solid #17263a",

        borderRadius: "7px",

        background: "#0a121e",

      }}

    >

      <span

        style={{

          display: "block",

          color: "#52647c",

          fontSize: "8px",

          fontWeight: 800,

          letterSpacing: "0.08em",

        }}

      >

        {label}

      </span>

      <strong

        style={{

          display: "block",

          marginTop: "5px",

          color: "#e2e8f0",

          fontSize: "14px",

          fontWeight: 700,

        }}

      >

        {value}

      </strong>

    </div>

  );

}

function Panel({

  title,

  subtitle,

  children,

}) {

  return (

    <section className="panel">

      <div className="panel-header">

        <div>

          <h2>{title}</h2>

          <p>{subtitle}</p>

        </div>

      </div>

      {children}

    </section>

  );

}

/* =========================================================

   CREDENTIAL PANEL

   ========================================================= */

function CredentialPanel({

  title,

  subtitle,

  data,

  valueLabel,

}) {

  return (

    <Panel

      title={title}

      subtitle={subtitle}

    >

      {data.length > 0 ? (

        <div className="table-wrapper">

          <table className="attack-table">

            <thead>

              <tr>

                <th>{valueLabel}</th>

                <th>COUNT</th>

              </tr>

            </thead>

            <tbody>

              {data.slice(0, 10).map((item, index) => (

                <tr key={`${item.value}-${index}`}>

                  <td className="ip-cell">

                    {item.value}

                  </td>

                  <td>{item.count.toLocaleString()}</td>

                </tr>

              ))}

            </tbody>

          </table>

        </div>

      ) : (

        <EmptyState

          text={`No ${valueLabel.toLowerCase()} data for this filter.`}

        />

      )}

    </Panel>

  );

}

/* =========================================================

   ATTACKERS TABLE

   ========================================================= */

function AttackersTable({ attackers }) {

  if (!attackers.length) {

    return (

      <EmptyState text="No attacker data for this filter." />

    );

  }

  return (

    <div className="table-wrapper">

      <table className="attack-table">

        <thead>

          <tr>

            <th>IP ADDRESS</th>

            <th>SESSIONS</th>

            <th>FAILED</th>

            <th>SUCCESS</th>

          </tr>

        </thead>

        <tbody>

          {attackers.slice(0, 7).map((attacker) => (

            <tr key={attacker.src_ip}>

              <td className="ip-cell">

                {attacker.src_ip}

              </td>

              <td>

                {attacker.sessions.toLocaleString()}

              </td>

              <td>

                {attacker.failed_logins.toLocaleString()}

              </td>

              <td className="success-cell">

                {attacker.successful_sessions.toLocaleString()}

              </td>

            </tr>

          ))}

        </tbody>

      </table>

    </div>

  );

}

/* =========================================================

   EMPTY STATE

   ========================================================= */

function EmptyState({ text }) {

  return (

    <div className="empty-state">

      {text}

    </div>

  );

}

export default App;
