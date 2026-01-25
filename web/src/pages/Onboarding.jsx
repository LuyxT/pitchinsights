import { useState } from "react";
import Card from "../components/Card.tsx";
import SectionHeader from "../components/SectionHeader.tsx";
import Input from "../components/Input.tsx";
import PageLayout from "../components/PageLayout.tsx";
import { fetchJson } from "../lib/api.js";

export default function Onboarding({ onNavigate }) {
  const [form, setForm] = useState({ verein: "", mannschaft: "", rolle: "Trainer" });
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState("");

  const handleChange = (field) => (event) => {
    setForm((prev) => ({ ...prev, [field]: event.target.value }));
  };

  const handleSave = async () => {
    setSaving(true);
    setStatus("");
    try {
      await fetchJson("/api/onboarding/complete", {
        method: "POST",
        body: JSON.stringify(form),
      });
      setStatus("Onboarding abgeschlossen");
      onNavigate("/dashboard");
    } catch (err) {
      setStatus(err.message || "Speichern fehlgeschlagen");
    } finally {
      setSaving(false);
    }
  };

  return (
    <PageLayout title="Onboarding" subtitle="Grunddaten für dein Team.">
      <SectionHeader title="Teamdetails" actionLabel={saving ? "Speichern..." : "Speichern"} onAction={handleSave} />
      <div className="card-grid">
        <Card>
          <Input label="Vereinsname" placeholder="Club" value={form.verein} onChange={handleChange("verein")} />
          <div style={{ height: 16 }} />
          <Input label="Mannschaft" placeholder="1. Mannschaft" value={form.mannschaft} onChange={handleChange("mannschaft")} />
        </Card>
        <Card>
          <Input label="Saison" placeholder="2024/25" />
          <div style={{ height: 16 }} />
          <Input label="Rolle" placeholder="trainer" value={form.rolle} onChange={handleChange("rolle")} />
          {status ? <div className="page-subtitle" style={{ marginTop: 12 }}>{status}</div> : null}
        </Card>
      </div>
    </PageLayout>
  );
}
