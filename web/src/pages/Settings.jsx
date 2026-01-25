import { useEffect, useState } from "react";
import SectionHeader from "../components/SectionHeader.tsx";
import Card from "../components/Card.tsx";
import Input from "../components/Input.tsx";
import LoadingState from "../components/LoadingState.tsx";
import PageLayout from "../components/PageLayout.tsx";
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
    <PageLayout title="Einstellungen" subtitle="Konto und Organisation an einem Ort.">
      <SectionHeader title="Profil" actionLabel={saving ? "Speichern..." : "Speichern"} onAction={handleSave} />
      {loading ? (
        <LoadingState rows={4} />
      ) : (
        <div className="card-grid">
          <Card>
            <Input label="Vorname" placeholder="Vorname" value={form.vorname} onChange={handleChange("vorname")} />
            <div style={{ height: 16 }} />
            <Input label="Nachname" placeholder="Nachname" value={form.nachname} onChange={handleChange("nachname")} />
            <div style={{ height: 16 }} />
            <Input label="Telefon" placeholder="Telefon" value={form.telefon} onChange={handleChange("telefon")} />
            {status ? <div className="page-subtitle" style={{ marginTop: 12 }}>{status}</div> : null}
          </Card>
          <Card>
            <Input
              label="E-Mail"
              type="email"
              placeholder="name@club.de"
              value={profile?.email || ""}
              readOnly
            />
            <div style={{ height: 16 }} />
            <Input label="Rolle" placeholder="Trainer" value={profile?.rolle || ""} readOnly />
          </Card>
        </div>
      )}
    </PageLayout>
  );
}
