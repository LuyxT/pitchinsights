import Card from "../components/Card.jsx";

export default function PaymentPending() {
  return (
    <div className="page">
      <div>
        <div className="page-title">Zahlung ausstehend</div>
        <div className="page-subtitle">Dein Zugriff wird nach Zahlung aktiviert.</div>
      </div>
      <Card>
        <div className="page-subtitle">Bei Fragen wende dich an den Support.</div>
      </Card>
    </div>
  );
}
