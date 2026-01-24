import { useEffect, useState } from "react";
import Card from "../components/Card.jsx";
import SectionHeader from "../components/SectionHeader.jsx";
import LoadingState from "../components/LoadingState.jsx";
import { fetchJson } from "../lib/api.js";

export default function Player() {
  const [profile, setProfile] = useState(null);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const [profileData, eventsData] = await Promise.all([
          fetchJson("/api/profile"),
          fetchJson("/api/player/next-events"),
        ]);
        if (!active) return;
        setProfile(profileData);
        setEvents(eventsData.events || []);
      } catch (err) {
        if (!active) return;
        setProfile(null);
        setEvents([]);
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
    };
  }, []);

  return (
    <div className="page">
      <div>
        <div className="page-title">Spielerprofil</div>
        <div className="page-subtitle">Detailansicht mit Leistung und Anwesenheit.</div>
      </div>
      <SectionHeader title="Profil" />
      {loading ? (
        <LoadingState rows={4} />
      ) : (
        <div className="card-grid">
          <Card>
            <div className="section-title">Übersicht</div>
            <div className="page-subtitle" style={{ marginTop: 12 }}>
              {profile ? `${profile.vorname || ""} ${profile.nachname || ""}`.trim() : "–"}
            </div>
            {profile?.position ? <div className="page-subtitle">Position · {profile.position}</div> : null}
            {profile?.starker_fuss ? <div className="page-subtitle">Starker Fuß · {profile.starker_fuss}</div> : null}
          </Card>
          <Card>
            <div className="section-title">Verletzungshistorie</div>
            <div className="page-subtitle" style={{ marginTop: 12 }}>
              {profile?.verletzungshistorie || "Keine Einträge"}
            </div>
          </Card>
          <Card>
            <div className="section-title">Nächste Termine</div>
            <div style={{ display: "grid", gap: 8, marginTop: 12 }}>
              {events.length ? (
                events.map((event) => (
                  <div key={event.id} className="page-subtitle">
                    {event.title} · {event.event_date}
                  </div>
                ))
              ) : (
                <div className="page-subtitle">Keine Termine</div>
              )}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
