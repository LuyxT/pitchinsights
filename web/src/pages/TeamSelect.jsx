import Card from "../components/Card.jsx";
import SectionHeader from "../components/SectionHeader.jsx";

export default function TeamSelect() {
  return (
    <div className="page">
      <div>
        <div className="page-title">Team auswählen</div>
        <div className="page-subtitle">Wähle die aktive Mannschaft.</div>
      </div>
      <SectionHeader title="Teams" />
      <div className="card-grid">
        <Card interactive>1. Mannschaft</Card>
        <Card interactive>U19</Card>
        <Card interactive>U17</Card>
      </div>
    </div>
  );
}
