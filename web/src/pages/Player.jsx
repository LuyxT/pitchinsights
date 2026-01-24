import Card from "../components/Card.jsx";
import SectionHeader from "../components/SectionHeader.jsx";

export default function Player() {
  return (
    <div className="page">
      <div>
        <div className="page-title">Spielerprofil</div>
        <div className="page-subtitle">Detailansicht mit Leistung und Anwesenheit.</div>
      </div>
      <SectionHeader title="Profil" />
      <div className="card-grid">
        <Card>Profilübersicht</Card>
        <Card>Leistungsdaten</Card>
        <Card>Anwesenheit</Card>
      </div>
    </div>
  );
}
