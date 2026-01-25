import { useState } from "react";
import SectionHeader from "../components/SectionHeader.tsx";
import Card from "../components/Card.tsx";
import Input from "../components/Input.tsx";
import Button from "../components/Button.tsx";
import PageLayout from "../components/PageLayout.tsx";
import { fetchJson } from "../lib/api.js";

export default function Training() {
  const [form, setForm] = useState({
    title: "",
    date: "",
    time: "",
    notes: "",
  });
  const [status, setStatus] = useState("");
  const [saving, setSaving] = useState(false);

  const handleChange = (field) => (event) => {
    setForm((prev) => ({ ...prev, [field]: event.target.value }));
  };

  const handleSave = async () => {
    setSaving(true);
    setStatus("");
    try {
      await fetchJson("/api/events", {
        method: "POST",
        body: JSON.stringify({
          title: form.title || "Training",
          date: form.date,
          time: form.time,
          description: form.notes,
          event_type: "training",
        }),
      });
      setStatus("Training gespeichert");
      setForm({ title: "", date: "", time: "", notes: "" });
    } catch (err) {
      setStatus(err.message || "Speichern fehlgeschlagen");
    } finally {
      setSaving(false);
    }
  };

  return (
    <PageLayout title="Trainingsplanung" subtitle="Schritte klar strukturieren und logisch gruppieren.">
      <SectionHeader
        title="Neues Training"
        actionLabel={saving ? "Speichern..." : "Speichern"}
        onAction={handleSave}
      />
      <div className="card-grid">
        <Card>
          <div className="section-title">Datum & Zeit</div>
          <div style={{ display: "grid", gap: 16, marginTop: 16 }}>
            <Input label="Datum" type="date" value={form.date} onChange={handleChange("date")} />
            <Input label="Uhrzeit" type="time" value={form.time} onChange={handleChange("time")} />
          </div>
        </Card>
        <Card>
          <div className="section-title">Übungen</div>
          <div style={{ display: "grid", gap: 16, marginTop: 16 }}>
            <Input
              label="Schwerpunkt"
              placeholder="z. B. Umschalten"
              value={form.title}
              onChange={handleChange("title")}
            />
            <Input
              label="Notizen"
              placeholder="Optionale Details"
              value={form.notes}
              onChange={handleChange("notes")}
            />
          </div>
        </Card>
        <Card>
          <div className="section-title">Spieler:innen</div>
          <div style={{ marginTop: 16 }}>
            <Button variant="secondary">Kader auswählen</Button>
          </div>
        </Card>
        <Card>
          <div className="section-title">Notizen</div>
          <div style={{ marginTop: 16 }}>
            <Input label="Zusatz" placeholder="Kurz und klar" value={form.notes} onChange={handleChange("notes")} />
            {status ? <div className="page-subtitle" style={{ marginTop: 12 }}>{status}</div> : null}
          </div>
        </Card>
      </div>
    </PageLayout>
  );
}
