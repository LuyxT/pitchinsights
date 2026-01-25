import Card from "../components/Card.tsx";
import Input from "../components/Input.tsx";
import Button from "../components/Button.tsx";
import PageLayout from "../components/PageLayout.tsx";

export default function TwoFactor() {
  return (
    <PageLayout title="2‑Faktor‑Bestätigung" subtitle="Gib deinen Bestätigungscode ein.">
      <Card>
        <div style={{ display: "grid", gap: 16 }}>
          <Input label="Code" name="code" placeholder="123456" />
          <Button>Bestätigen</Button>
        </div>
      </Card>
    </PageLayout>
  );
}
