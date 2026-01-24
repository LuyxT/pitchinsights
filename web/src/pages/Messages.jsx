import SectionHeader from "../components/SectionHeader.jsx";
import Card from "../components/Card.jsx";
import EmptyState from "../components/EmptyState.jsx";

export default function Messages() {
  const hasMessages = false;
  return (
    <div className="page">
      <div>
        <div className="page-title">Nachrichten</div>
        <div className="page-subtitle">Kommunikation klar und gebündelt.</div>
      </div>
      <SectionHeader title="Teamchat" actionLabel="Nachricht schreiben" />
      {hasMessages ? (
        <Card>Chatverlauf</Card>
      ) : (
        <EmptyState
          title="Noch keine Nachrichten"
          description="Schreibe eine Nachricht, um den Austausch zu starten."
          actionLabel="Nachricht schreiben"
        />
      )}
    </div>
  );
}
