import SectionHeader from "../components/SectionHeader.jsx";
import Card from "../components/Card.jsx";
import EmptyState from "../components/EmptyState.jsx";

export default function Calendar() {
  const hasEvents = false;
  return (
    <div className="page">
      <div>
        <div className="page-title">Kalender</div>
        <div className="page-subtitle">Alle Trainings und Spiele im Überblick.</div>
      </div>
      <SectionHeader title="Woche" actionLabel="Termin hinzufügen" />
      {hasEvents ? (
        <Card>Kalenderansicht</Card>
      ) : (
        <EmptyState
          title="Noch keine Termine"
          description="Füge einen Termin hinzu, um die Woche zu planen."
          actionLabel="Termin hinzufügen"
        />
      )}
    </div>
  );
}
