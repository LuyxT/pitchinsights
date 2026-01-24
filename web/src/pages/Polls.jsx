import SectionHeader from "../components/SectionHeader.jsx";
import Card from "../components/Card.jsx";
import EmptyState from "../components/EmptyState.jsx";

export default function Polls() {
  const hasPolls = false;
  return (
    <div className="page">
      <div>
        <div className="page-title">Abstimmungen</div>
        <div className="page-subtitle">Zusagen und Absagen im eigenen Bereich.</div>
      </div>
      <SectionHeader title="Aktive Abstimmungen" actionLabel="Abstimmung erstellen" />
      {hasPolls ? (
        <Card>Abstimmungen</Card>
      ) : (
        <EmptyState
          title="Noch keine Abstimmungen"
          description="Erstelle eine Abstimmung, um Anwesenheiten einzuholen."
          actionLabel="Abstimmung erstellen"
        />
      )}
    </div>
  );
}
