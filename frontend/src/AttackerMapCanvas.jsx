import { CircleMarker, MapContainer, Popup, TileLayer, useMap } from "react-leaflet";
import "leaflet/dist/leaflet.css";

function FocusMarker({ point, sessions, failed, selected, onSelect }) {
  const map = useMap();
  const latitude = Number(point.latitude);
  const longitude = Number(point.longitude);
  const baseRadius = Math.max(5, Math.min(15, 5 + Math.sqrt(sessions) * 1.05));
  const radius = selected ? Math.min(baseRadius + 4, 19) : baseRadius;
  const riskLevel = String(point.risk_level || "Unknown");
  const riskColors = {
    High: { color: "#ef4444", glow: "#f87171" },
    Medium: { color: "#f59e0b", glow: "#fbbf24" },
    Low: { color: "#22c55e", glow: "#4ade80" },
    Unknown: { color: "#64748b", glow: "#94a3b8" },
  };
  const riskColor = riskColors[riskLevel] || riskColors.Low;

  function handleClick() {
    onSelect(point.src_ip);
    map.flyTo([latitude, longitude], Math.max(map.getZoom(), 4), { duration: 0.8 });
  }

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
            <span className="map-popup-risk" style={{ borderColor: riskColor.color, color: riskColor.color }}>
              {riskLevel}
            </span>
          </div>
          <div className="map-popup-location">
            {point.city && point.country ? `${point.city}, ${point.country}` : point.country || "Unknown location"}
          </div>
          <div className="map-popup-divider" />
          <div className="map-popup-stat-grid">
            <div><span>ATTACK EVENTS</span><strong>{Number(point.total_events ?? sessions).toLocaleString()}</strong></div>
            <div><span>FAILED LOGINS</span><strong>{failed.toLocaleString()}</strong></div>
          </div>
          <div className="map-popup-note">Approximate IP geolocation</div>
        </div>
      </Popup>
    </CircleMarker>
  );
}

export default function AttackerMapCanvas({ data, selectedIp, onSelect, onTileStatus }) {
  return (
    <MapContainer
      center={[20, 0]}
      zoom={2}
      minZoom={2}
      maxZoom={7}
      scrollWheelZoom
      worldCopyJump
      className="attacker-map-container"
    >
      <TileLayer
        attribution="&copy; OpenStreetMap contributors"
        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        eventHandlers={{
          tileerror: () => onTileStatus(true),
          tileload: () => onTileStatus(false),
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
            onSelect={onSelect}
          />
        );
      })}
    </MapContainer>
  );
}
