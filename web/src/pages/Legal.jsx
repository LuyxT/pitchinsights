import Card from "../components/Card.tsx";
import PageLayout from "../components/PageLayout.tsx";

export default function Legal({ title }) {
  return (
    <PageLayout title={title} subtitle="Rechtliche Informationen.">
      <Card>
        <div className="page-subtitle">Inhalt folgt.</div>
      </Card>
    </PageLayout>
  );
}
