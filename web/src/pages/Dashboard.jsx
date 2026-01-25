import { useEffect, useMemo, useState } from "react";
import Card from "../components/Card.tsx";
import SectionHeader from "../components/SectionHeader.tsx";
import EmptyState from "../components/EmptyState.tsx";
import LoadingState from "../components/LoadingState.tsx";
import PageLayout from "../components/PageLayout.tsx";
import { fetchJson } from "../lib/api.js";

const formatDate = (value) => {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString("de-DE", { weekday: "short", day: "2-digit", month: "2-digit" });
};

export default function Dashboard({ onNavigate }) {
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [unread, setUnread] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const [weekData, statsData, unreadData] = await Promise.all([
          fetchJson("/api/events/week"),
          fetchJson("/api/players/stats"),
          fetchJson("/api/messages/unread"),
        ]);
        if (!active) return;
        setEvents(weekData.events || []);
        setStats(statsData || null);
        setUnread(unreadData?.count || 0);
      } catch (err) {
        if (!active) return;
        setEvents([]);
        setStats(null);
        setUnread(0);
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
    };
  }, []);

  const nextEvents = useMemo(() => events.slice(0, 3), [events]);
  const hasData = nextEvents.length > 0;

  return (
    <PageLayout title="Home" subtitle="Überblick über Trainings, Spieler:innen und nächste Termine.">
      <SectionHeader
        title="Nächste Termine"
        actionLabel="Neues Training"
        onAction={() => onNavigate("/calendar")}
      />
      {loading ? (
        <LoadingState rows={3} />
      ) : hasData ? (
        <div className="card-grid">
          {nextEvents.map((event) => (
            <Card key={event.id}>
              <div className="section-title">{event.title}</div>
              <div className="page-subtitle" style={{ marginTop: 8 }}>
                {formatDate(event.event_date)} · {event.start_time || "offen"}
              </div>
            </Card>
          ))}
        </div>
      ) : (
        <EmptyState
          title="Noch keine Termine"
          description="Erstelle dein erstes Training oder einen Spieltermin."
          actionLabel="Neues Training"
          onAction={() => onNavigate("/calendar")}
        />
      )}
      <SectionHeader title="Kennzahlen" />
      <div className="card-grid">
        <Card>
          <div className="section-title">Trainingsbeteiligung</div>
          <div style={{ marginTop: 8, fontSize: "var(--text-xl)", fontWeight: 700 }}>
            {stats ? `${Math.round((stats.fit / (stats.total || 1)) * 100)}%` : "–"}
          </div>
        </Card>
        <Card>
          <div className="section-title">Verfügbare Spieler:innen</div>
          <div style={{ marginTop: 8, fontSize: "var(--text-xl)", fontWeight: 700 }}>
            {stats ? stats.fit : "–"}
          </div>
        </Card>
        <Card>
          <div className="section-title">Offene Rückmeldungen</div>
          <div style={{ marginTop: 8, fontSize: "var(--text-xl)", fontWeight: 700 }}>
            {unread || "0"}
          </div>
        </Card>
      </div>
    </PageLayout>
  );
}
