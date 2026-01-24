import { useEffect, useState } from "react";
import Card from "../components/Card.jsx";
import SectionHeader from "../components/SectionHeader.jsx";
import LoadingState from "../components/LoadingState.jsx";
import EmptyState from "../components/EmptyState.jsx";
import { fetchJson } from "../lib/api.js";

export default function TeamSelect({ onNavigate }) {
  const [memberships, setMemberships] = useState([]);
  const [activeTeamId, setActiveTeamId] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const data = await fetchJson("/api/memberships");
        if (!active) return;
        setMemberships(data.memberships || []);
        setActiveTeamId(data.active_team_id || null);
      } catch (err) {
        if (!active) return;
        setMemberships([]);
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
    };
  }, []);

  const handleSelect = async (teamId) => {
    await fetchJson("/api/memberships/active", {
      method: "POST",
      body: JSON.stringify({ team_id: teamId }),
    });
    onNavigate("/dashboard");
  };

  return (
    <div className="page">
      <div>
        <div className="page-title">Team auswählen</div>
        <div className="page-subtitle">Wähle die aktive Mannschaft.</div>
      </div>
      <SectionHeader title="Teams" />
      {loading ? (
        <LoadingState rows={3} />
      ) : memberships.length ? (
        <div className="card-grid">
          {memberships.map((membership) => (
            <Card
              key={membership.team_id}
              interactive
              onClick={() => handleSelect(membership.team_id)}
            >
              <div className="section-title">{membership.team_name || membership.team_id}</div>
              <div className="page-subtitle" style={{ marginTop: 8 }}>
                {membership.role_name || "Mitglied"}
                {activeTeamId === membership.team_id ? " · Aktiv" : ""}
              </div>
            </Card>
          ))}
        </div>
      ) : (
        <EmptyState
          title="Keine Teams gefunden"
          description="Du bist noch keinem Team zugeordnet."
          actionLabel="Dashboard"
          onAction={() => onNavigate("/dashboard")}
        />
      )}
    </div>
  );
}
