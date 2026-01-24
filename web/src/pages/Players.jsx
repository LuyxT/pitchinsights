import SectionHeader from "../components/SectionHeader.jsx";
import Card from "../components/Card.jsx";
import List from "../components/List.jsx";

const samplePlayers = [
  { id: 1, title: "M. Schneider", subtitle: "Torhüter · Fit", meta: "Tor" },
  { id: 2, title: "L. Baum", subtitle: "Innenverteidiger · Fit", meta: "IV" },
  { id: 3, title: "N. Klein", subtitle: "Stürmer · Reha", meta: "ST" },
];

export default function Players() {
  return (
    <div className="page">
      <div>
        <div className="page-title">Spieler:innen</div>
        <div className="page-subtitle">Kaderübersicht mit konsistenten Aktionen.</div>
      </div>
      <SectionHeader title="Kaderliste" actionLabel="Spieler:in hinzufügen" />
      <Card>
        <List items={samplePlayers} />
      </Card>
    </div>
  );
}
