import { useState } from "react";
import Card from "../components/Card.jsx";
import SectionHeader from "../components/SectionHeader.jsx";
import InputField from "../components/InputField.jsx";
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
    <div className="page">
      <div>
        <div className="page-title">Onboarding</div>
        <div className="page-subtitle">Grunddaten für dein Team.</div>
      </div>
      <SectionHeader title="Teamdetails" actionLabel={saving ? "Speichern..." : "Speichern"} onAction={handleSave} />
      <div className="card-grid">
        <Card>
          <InputField label="Vereinsname" placeholder="Club" value={form.verein} onChange={handleChange("verein")} />
          <div style={{ height: 16 }} />
          <InputField label="Mannschaft" placeholder="1. Mannschaft" value={form.mannschaft} onChange={handleChange("mannschaft")} />
        </Card>
        <Card>
          <InputField label="Saison" placeholder="2024/25" />
          <div style={{ height: 16 }} />
          <InputField label="Rolle" placeholder="trainer" value={form.rolle} onChange={handleChange("rolle")} />
          {status ? <div className="page-subtitle" style={{ marginTop: 12 }}>{status}</div> : null}
        </Card>
      </div>
    </div>
  );
}
