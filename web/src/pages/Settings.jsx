import { useEffect, useState } from "react";
import SectionHeader from "../components/SectionHeader.jsx";
import Card from "../components/Card.jsx";
import InputField from "../components/InputField.jsx";
import LoadingState from "../components/LoadingState.jsx";
import { fetchJson } from "../lib/api.js";

export default function Settings() {
  const [profile, setProfile] = useState(null);
  const [form, setForm] = useState({ vorname: "", nachname: "", telefon: "" });
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState("");

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const data = await fetchJson("/api/profile");
        if (!active) return;
        setProfile(data);
        setForm({
          vorname: data.vorname || "",
          nachname: data.nachname || "",
          telefon: data.telefon || "",
        });
      } catch (err) {
        if (!active) return;
        setProfile(null);
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
    };
  }, []);

  const handleChange = (field) => (event) => {
    setForm((prev) => ({ ...prev, [field]: event.target.value }));
  };

  const handleSave = async () => {
    setSaving(true);
    setStatus("");
    try {
      const data = await fetchJson("/api/profile", {
        method: "POST",
        body: JSON.stringify(form),
      });
      setStatus(data.success ? "Gespeichert" : "");
    } catch (err) {
      setStatus(err.message || "Speichern fehlgeschlagen");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="page">
      <div>
        <div className="page-title">Einstellungen</div>
        <div className="page-subtitle">Konto und Organisation an einem Ort.</div>
      </div>
      <SectionHeader title="Profil" actionLabel={saving ? "Speichern..." : "Speichern"} onAction={handleSave} />
      {loading ? (
        <LoadingState rows={4} />
      ) : (
        <div className="card-grid">
          <Card>
            <InputField label="Vorname" placeholder="Vorname" value={form.vorname} onChange={handleChange("vorname")} />
            <div style={{ height: 16 }} />
            <InputField label="Nachname" placeholder="Nachname" value={form.nachname} onChange={handleChange("nachname")} />
            <div style={{ height: 16 }} />
            <InputField label="Telefon" placeholder="Telefon" value={form.telefon} onChange={handleChange("telefon")} />
            {status ? <div className="page-subtitle" style={{ marginTop: 12 }}>{status}</div> : null}
          </Card>
          <Card>
            <InputField
              label="E-Mail"
              type="email"
              placeholder="name@club.de"
              value={profile?.email || ""}
              readOnly
            />
            <div style={{ height: 16 }} />
            <InputField label="Rolle" placeholder="Trainer" value={profile?.rolle || ""} readOnly />
          </Card>
        </div>
      )}
    </div>
  );
}
