import Card from "../components/Card.tsx";
import PageLayout from "../components/PageLayout.tsx";

export default function PaymentPending() {
  return (
    <PageLayout title="Zahlung ausstehend" subtitle="Dein Zugriff wird nach Zahlung aktiviert.">
      <Card>
        <div className="page-subtitle">Bei Fragen wende dich an den Support.</div>
      </Card>
    </PageLayout>
  );
}
