import { useEffect, useState } from "react";
import axios from "axios";
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from "react-leaflet";
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
  const [countries, setCountries] = useState([]);
  const [mapData, setMapData] = useState([]);
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
          countriesRes,
          mapRes,
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
          axios.get(`${API}/api/countries`, {
            params: {
              ...params,
              limit: 10,
            },
          }),
          axios.get(`${API}/api/map`, { params }),
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
        setCountries(countriesRes.data);
        setMapData(mapRes.data);
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
        {/* HEADER */}
        <header id="overview" className="dashboard-header">
          <div>
            <div className="eyebrow">
              SECURITY OPERATIONS
            </div>
            <h1>Honeypot Attack Overview</h1>
          </div>
          <div className="live-indicator">
            <span className="live-dot" />
            LIVE DATA
          </div>
        </header>
        {/* MONITORING */}
        <section className="monitoring-banner">
          <div>
            <div className="section-eyebrow">
              THREAT MONITORING
            </div>
            <h2>
              Attack activity across your honeypot infrastructure
            </h2>
          </div>
          <div className="time-range">
            <div>
              <span>First seen</span>
              <strong>
                {overview?.first_seen ||
                  meta?.first_day ||
                  "—"}
              </strong>
            </div>
            <div>
              <span>Last seen</span>
              <strong>
                {overview?.last_seen ||
                  meta?.last_day ||
                  "—"}
              </strong>
            </div>
          </div>
        </section>
        {/* FILTERS */}
        <section className="filter-bar">
          <div className="filter-group">
            <label>Start Date</label>
            <input
              type="date"
              value={startDate}
              min={meta?.first_day || ""}
              max={meta?.last_day || ""}
              onChange={(event) =>
                setStartDate(event.target.value)
              }
            />
          </div>
          <div className="filter-group">
            <label>End Date</label>
            <input
              type="date"
              value={endDate}
              min={meta?.first_day || ""}
              max={meta?.last_day || ""}
              onChange={(event) =>
                setEndDate(event.target.value)
              }
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
              <option value="">
                All Behaviors
              </option>
              {meta?.behaviors?.map((behavior) => (
                <option
                  key={behavior}
                  value={behavior}
                >
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
        {/* ERROR */}
        {error && (
          <div className="error-banner">
            <AlertTriangle size={18} />
            <span>{error}</span>
          </div>
        )}
        {/* ACTIVE FILTER */}
        {(filters.start ||
          filters.end ||
          filters.behavior) && (
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
                Behavior{" "}
                <strong>{filters.behavior}</strong>
              </span>
            )}
          </div>
        )}
        {/* KPI */}
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
        {/* TIMELINE + RISK */}
        <section className="dashboard-grid two-columns">
          <Panel
            title="Attack Timeline"
            subtitle="Sessions by day"
          >
            <div className="chart-container">
              {timelineChart.length > 0 ? (
                <ResponsiveContainer
                  width="100%"
                  height={310}
                >
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
                        border:
                          "1px solid #24364b",
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
                <EmptyState
                  text="No timeline data for this filter."
                />
              )}
            </div>
          </Panel>
          <Panel
            title="Risk Distribution"
            subtitle="Attacker risk levels"
          >
            <div className="chart-container">
              {riskChart.length > 0 ? (
                <ResponsiveContainer
                  width="100%"
                  height={310}
                >
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
                          fill={
                            riskColors[entry.name]
                          }
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: "#0b1320",
                        border:
                          "1px solid #24364b",
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
                <EmptyState
                  text="No risk data for this filter."
                />
              )}
            </div>
          </Panel>
        </section>
        {/* HOURLY */}
        <section className="dashboard-grid">
          <Panel
            title="Attack Activity by Hour"
            subtitle="Sessions observed across the 24-hour period"
          >
            <div className="chart-container">
              {formattedHourlyData.length > 0 ? (
                <ResponsiveContainer
                  width="100%"
                  height={300}
                >
                  <BarChart
                    data={formattedHourlyData}
                  >
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
                        border:
                          "1px solid #24364b",
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
                <EmptyState
                  text="No hourly activity for this filter."
                />
              )}
            </div>
          </Panel>
        </section>
        {/* BEHAVIOR + SOURCES */}
        <section id="threat-intelligence" className="dashboard-grid two-columns">
          <Panel
            title="Attack Behavior"
            subtitle="Session classification"
          >
            <div className="chart-container">
              {behaviorData.length > 0 ? (
                <ResponsiveContainer
                  width="100%"
                  height={330}
                >
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
                        border:
                          "1px solid #24364b",
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
                <EmptyState
                  text="No behavior data for this filter."
                />
              )}
            </div>
          </Panel>
          <Panel
            title="Top Attack Sources"
            subtitle="Highest activity IP addresses"
          >
            <AttackersTable
              attackers={attackers}
            />
          </Panel>
        </section>
        {/* CREDENTIAL INTELLIGENCE */}
        <section id="credentials" className="dashboard-grid three-columns">
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
        {/* ATTACKER MAP */}
        <section id="attack-sources" className="dashboard-grid">
          <Panel
            title="Attacker Origin Map"
            subtitle="Approximate geographic distribution of observed attack sources"
          >
            <AttackerMap data={mapData} filters={filters} />
          </Panel>
        </section>
        {/* GEOGRAPHIC + RISK */}
        <section className="dashboard-grid two-columns">
          <Panel
            title="Geographic Sources"
            subtitle="Attacker origin summary"
          >
            {countries.length > 0 ? (
              <div className="country-list">
                {countries.map(
                  (country, index) => (
                    <div
                      className="country-row"
                      key={`${country.country}-${index}`}
                    >
                      <div className="country-name">
                        <Globe size={18} />
                        <span>
                          {country.country}
                        </span>
                      </div>
                      <div className="country-stats">
                        <strong>
                          {country.sessions.toLocaleString()}
                        </strong>
                        <span>
                          sessions
                        </span>
                      </div>
                    </div>
                  )
                )}
              </div>
            ) : (
              <EmptyState
                text="No geographic data for this filter."
              />
            )}
          </Panel>
          <Panel
            title="Highest Risk Attackers"
            subtitle="Risk-ranked IP addresses"
          >
            <div className="risk-list">
              {attackers.length > 0 ? (
                attackers
                  .slice(0, 5)
                  .map((attacker) => (
                    <div
                      className="risk-row"
                      key={attacker.src_ip}
                    >
                      <div className="risk-ip">
                        <strong>
                          {attacker.src_ip}
                        </strong>
                        <span>
                          {attacker.sessions.toLocaleString()}{" "}
                          sessions
                        </span>
                      </div>
                      <RiskBadge
                        level={
                          attacker.risk_level
                        }
                      />
                      <strong className="risk-score">
                        {Number(
                          attacker.risk_score
                        ).toFixed(1)}
                      </strong>
                    </div>
                  ))
              ) : (
                <EmptyState
                  text="No risk data for this filter."
                />
              )}
            </div>
          </Panel>
        </section>
        <footer className="dashboard-footer">
          <div>
            Honeypot Attack Analytics
          </div>
          <div>
            FastAPI + React
          </div>
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

    const handleHashChange = () => {
      const hash = window.location.hash.replace("#", "");

      if (sections.includes(hash)) {
        setActiveSection(hash);
      }
    };

    handleHashChange();

    window.addEventListener("hashchange", handleHashChange);

    return () => {
      window.removeEventListener("hashchange", handleHashChange);
    };
  }, []);

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-icon">
          <Shield />
        </div>

        <div>
          <div className="brand-title">
            Honeypot
          </div>

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

/* =========================================================
   PANEL
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
  const baseRadius = Math.max(5, Math.min(15, 5 + Math.sqrt(sessions) * 1.05));
  const radius = selected ? Math.min(baseRadius + 4, 19) : baseRadius;
  const riskLevel = String(point.risk_level || "Low");
  const riskColors = {
    High: { color: "#ef4444", glow: "#f87171" },
    Medium: { color: "#f59e0b", glow: "#fbbf24" },
    Low: { color: "#22c55e", glow: "#4ade80" },
  };
  const riskColor = riskColors[riskLevel] || riskColors.Low;
  const handleClick = () => {
    onSelect(point.src_ip);
    map.flyTo([latitude, longitude], Math.max(map.getZoom(), 4), {
      duration: 0.8,
    });
  };
  return (
    <CircleMarker
      center={[latitude, longitude]}
      radius={radius}
      eventHandlers={{ click: handleClick }}
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
            <div className="map-popup-ip">{point.src_ip}</div>
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
              <span>SESSIONS</span>
              <strong>{sessions.toLocaleString()}</strong>
            </div>
            <div>
              <span>FAILED LOGINS</span>
              <strong>{failed.toLocaleString()}</strong>
            </div>
          </div>
          <div className="map-popup-note">Approximate IP geolocation</div>
        </div>
      </Popup>
    </CircleMarker>
  );
}
function AttackerMap({ data, filters }) {
  const [selectedIp, setSelectedIp] = useState(null);
  const [profile, setProfile] = useState(null);
  const [profileLoading, setProfileLoading] = useState(false);
  const [profileError, setProfileError] = useState("");
  useEffect(() => {
  if (!selectedIp) {
    return;
  }

  const attackerStillVisible = data.some(
    (point) => point.src_ip === selectedIp
  );

  if (!attackerStillVisible) {
    setSelectedIp(null);
    setProfile(null);
    setProfileError("");
    setProfileLoading(false);
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
  if (!data.length) {
    return <EmptyState text="No geolocation data for this filter." />;
  }
  return (
    <div className="attacker-map">
      <MapContainer
        center={[20, 0]}
        zoom={2}
        minZoom={2}
        maxZoom={7}
        scrollWheelZoom={true}
        worldCopyJump={true}
        className="attacker-map-container"
      >
        <TileLayer
          attribution='&copy; OpenStreetMap contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        {data.map((point) => {
          const sessions = Number(point.sessions || 0);
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
      </MapContainer>
      <div className="map-footer">
        <div className="map-legend">
          <span className="map-legend-title">RISK LEVEL</span>
          <span className="map-legend-item"><i className="map-legend-dot low" /> Low</span>
          <span className="map-legend-item"><i className="map-legend-dot medium" /> Medium</span>
          <span className="map-legend-item"><i className="map-legend-dot high" /> High</span>
        </div>
        <span className="map-count">{data.length} attacker IPs mapped</span>
      </div>
      <div className="map-disclaimer">
        IP geolocation is approximate and represents the registered geographic location of the source IP, not the exact physical location of an attacker.
      </div>
      {selectedIp && (
        <section className="attacker-profile-panel">
          {profileLoading ? (
            <div className="attacker-profile-loading">Loading attacker intelligence…</div>
          ) : profileError ? (
            <div className="attacker-profile-error">{profileError}</div>
          ) : profile ? (
            <>
              <div className="attacker-profile-header">
                <div>
                  <div className="attacker-profile-kicker">ATTACKER INTELLIGENCE</div>
                  <div className="attacker-profile-ip">{profile.src_ip}</div>
                  <div className="attacker-profile-location">
                    {profile.city ? `${profile.city}, ` : ""}{profile.country || "Unknown location"}
                  </div>
                </div>
                <div className="attacker-profile-risk-wrap">
                  <span className={`attacker-profile-risk ${String(profile.risk_level || "").toLowerCase()}`}>
                    {profile.risk_level || "Unknown"}
                  </span>
                  <button className="attacker-profile-close" onClick={() => setSelectedIp(null)}>Close</button>
                </div>
              </div>
              <div className="attacker-profile-stats">
                <div className="attacker-profile-stat">
                  <span>RISK SCORE</span>
                  <strong>{Number(profile.risk_score || 0).toFixed(1)} / 100</strong>
                </div>
                <div className="attacker-profile-stat">
                  <span>SESSIONS</span>
                  <strong>{Number(profile.sessions || 0).toLocaleString()}</strong>
                </div>
                <div className="attacker-profile-stat">
                  <span>FAILED LOGINS</span>
                  <strong>{Number(profile.failed_logins || 0).toLocaleString()}</strong>
                </div>
                <div className="attacker-profile-stat">
                  <span>SUCCESSFUL</span>
                  <strong>{Number(profile.successful_sessions || 0).toLocaleString()}</strong>
                </div>
                <div className="attacker-profile-stat">
                  <span>COMMANDS</span>
                  <strong>{Number(profile.commands || 0).toLocaleString()}</strong>
                </div>
              </div>
              <div className="attacker-profile-meta">
                <div><span>FIRST SEEN</span><strong>{profile.first_seen || "—"}</strong></div>
                <div><span>LAST SEEN</span><strong>{profile.last_seen || "—"}</strong></div>
                <div><span>BEHAVIOR</span><strong>{profile.behavior || "Unclustered"}</strong></div>
              </div>
              <div className="attacker-profile-columns">
                <div className="attacker-profile-list">
                  <div className="attacker-profile-list-title">TARGETED USERNAMES</div>
                  {profile.usernames?.length ? profile.usernames.map((item) => (
                    <div className="attacker-profile-list-row" key={item.value}>
                      <span>{item.value}</span><strong>{item.count}</strong>
                    </div>
                  )) : <span className="attacker-profile-empty">No usernames observed</span>}
                </div>
                <div className="attacker-profile-list">
                  <div className="attacker-profile-list-title">TARGETED PASSWORDS</div>
                  {profile.passwords?.length ? profile.passwords.map((item) => (
                    <div className="attacker-profile-list-row" key={item.value}>
                      <span>{item.value}</span><strong>{item.count}</strong>
                    </div>
                  )) : <span className="attacker-profile-empty">No passwords observed</span>}
                </div>
                <div className="attacker-profile-list">
                  <div className="attacker-profile-list-title">OBSERVED COMMANDS</div>
                  {profile.commands_top?.length ? profile.commands_top.map((item) => (
                    <div className="attacker-profile-list-row" key={item.value}>
                      <span title={item.value}>{item.value}</span><strong>{item.count}</strong>
                    </div>
                  )) : <span className="attacker-profile-empty">No commands observed</span>}
                </div>
              </div>
            </>
          ) : null}
        </section>
      )}
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
              {data.slice(0, 10).map(
                (item, index) => (
                  <tr key={`${item.value}-${index}`}>
                    <td className="ip-cell">
                      {item.value}
                    </td>
                    <td>
                      {item.count.toLocaleString()}
                    </td>
                  </tr>
                )
              )}
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
function AttackersTable({
  attackers,
}) {
  if (!attackers.length) {
    return (
      <EmptyState
        text="No attacker data for this filter."
      />
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
          {attackers
            .slice(0, 7)
            .map((attacker) => (
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
