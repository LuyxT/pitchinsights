import { useEffect, useState } from "react";
import SectionHeader from "../components/SectionHeader.jsx";
import Card from "../components/Card.jsx";
import List from "../components/List.jsx";
import EmptyState from "../components/EmptyState.jsx";
import LoadingState from "../components/LoadingState.jsx";
import { fetchJson } from "../lib/api.js";

export default function Players() {
  const [players, setPlayers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const data = await fetchJson("/api/players");
        if (!active) return;
        setPlayers(data.players || []);
      } catch (err) {
        if (!active) return;
        setPlayers([]);
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
    };
  }, []);

  const items = players.map((player) => ({
    id: player.id,
    title: player.name || "Ohne Namen",
    subtitle: [player.position, player.status].filter(Boolean).join(" · "),
    meta: player.trikotnummer ? `#${player.trikotnummer}` : null,
  }));

  return (
    <div className="page">
      <div>
        <div className="page-title">Spieler:innen</div>
        <div className="page-subtitle">Kaderübersicht mit konsistenten Aktionen.</div>
      </div>
      <SectionHeader title="Kaderliste" actionLabel="Spieler:in hinzufügen" />
      {loading ? (
        <LoadingState rows={5} />
      ) : items.length ? (
        <Card>
          <List items={items} />
        </Card>
      ) : (
        <EmptyState
          title="Noch kein Kader"
          description="Füge Spieler:innen hinzu, um mit der Planung zu starten."
          actionLabel="Spieler:in hinzufügen"
        />
      )}
    </div>
  );
}
