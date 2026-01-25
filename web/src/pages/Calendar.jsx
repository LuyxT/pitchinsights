import { useEffect, useState } from "react";
import SectionHeader from "../components/SectionHeader.tsx";
import Card from "../components/Card.tsx";
import EmptyState from "../components/EmptyState.tsx";
import LoadingState from "../components/LoadingState.tsx";
import Badge from "../components/Badge.tsx";
import PageLayout from "../components/PageLayout.tsx";
import { fetchJson } from "../lib/api.js";

const formatDateTime = (event) => {
  const date = event.event_date ? new Date(event.event_date) : null;
  const dateLabel = date && !Number.isNaN(date.getTime())
    ? date.toLocaleDateString("de-DE", { weekday: "short", day: "2-digit", month: "2-digit" })
    : event.event_date || "";
  const timeLabel = event.start_time || "offen";
  return `${dateLabel} · ${timeLabel}`;
};

export default function Calendar() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const data = await fetchJson("/api/events");
        if (!active) return;
        setEvents(data.events || []);
      } catch (err) {
        if (!active) return;
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

  const hasEvents = events.length > 0;
  return (
    <PageLayout title="Kalender" subtitle="Alle Trainings und Spiele im Überblick.">
      <SectionHeader title="Woche" actionLabel="Termin hinzufügen" />
      {loading ? (
        <LoadingState rows={4} />
      ) : hasEvents ? (
        <Card>
          <div className="list">
            {events.map((event) => (
              <div key={event.id} className="list-row">
                <div>
                  <div>{event.title}</div>
                  <div className="page-subtitle">{formatDateTime(event)}</div>
                </div>
                {event.event_type ? (
                  <Badge>{event.event_type}</Badge>
                ) : null}
              </div>
            ))}
          </div>
        </Card>
      ) : (
        <EmptyState
          title="Noch keine Termine"
          description="Füge einen Termin hinzu, um die Woche zu planen."
          actionLabel="Termin hinzufügen"
        />
      )}
    </PageLayout>
  );
}
