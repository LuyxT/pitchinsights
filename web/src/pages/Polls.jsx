import { useEffect, useState } from "react";
import SectionHeader from "../components/SectionHeader.tsx";
import Card from "../components/Card.tsx";
import EmptyState from "../components/EmptyState.tsx";
import LoadingState from "../components/LoadingState.tsx";
import PageLayout from "../components/PageLayout.tsx";
import { fetchJson } from "../lib/api.js";

export default function Polls() {
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

  const hasPolls = events.length > 0;
  return (
    <PageLayout title="Abstimmungen" subtitle="Zusagen und Absagen im eigenen Bereich.">
      <SectionHeader title="Aktive Abstimmungen" actionLabel="Abstimmung erstellen" />
      {loading ? (
        <LoadingState rows={4} />
      ) : hasPolls ? (
        <Card>
          <div className="list">
            {events.map((event) => (
              <div key={event.id} className="list-row">
                <div>
                  <div>{event.title}</div>
                  <div className="page-subtitle">{event.event_date}</div>
                </div>
                <div className="page-subtitle">
                  {event.rsvp_summary ? `${event.rsvp_summary.yes || 0} Ja · ${event.rsvp_summary.no || 0} Nein` : "–"}
                </div>
              </div>
            ))}
          </div>
        </Card>
      ) : (
        <EmptyState
          title="Noch keine Abstimmungen"
          description="Erstelle eine Abstimmung, um Anwesenheiten einzuholen."
          actionLabel="Abstimmung erstellen"
        />
      )}
    </PageLayout>
  );
}
