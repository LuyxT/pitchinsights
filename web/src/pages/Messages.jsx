import { useEffect, useState } from "react";
import SectionHeader from "../components/SectionHeader.jsx";
import Card from "../components/Card.jsx";
import EmptyState from "../components/EmptyState.jsx";
import LoadingState from "../components/LoadingState.jsx";
import { fetchJson } from "../lib/api.js";

const formatTime = (value) => {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });
};

export default function Messages() {
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const data = await fetchJson("/api/messages?limit=15&scope=team");
        if (!active) return;
        setMessages(data.messages || []);
      } catch (err) {
        if (!active) return;
        setMessages([]);
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
    };
  }, []);

  const hasMessages = messages.length > 0;
  return (
    <div className="page">
      <div>
        <div className="page-title">Nachrichten</div>
        <div className="page-subtitle">Kommunikation klar und gebündelt.</div>
      </div>
      <SectionHeader title="Teamchat" actionLabel="Nachricht schreiben" />
      {loading ? (
        <LoadingState rows={4} />
      ) : hasMessages ? (
        <Card>
          <div className="list">
            {messages.map((message) => (
              <div key={message.id} className="list-row">
                <div>
                  <div>{message.sender_name || "Team"}</div>
                  <div className="page-subtitle">{message.content}</div>
                </div>
                <div className="page-subtitle">{formatTime(message.created_at)}</div>
              </div>
            ))}
          </div>
        </Card>
      ) : (
        <EmptyState
          title="Noch keine Nachrichten"
          description="Schreibe eine Nachricht, um den Austausch zu starten."
          actionLabel="Nachricht schreiben"
        />
      )}
    </div>
  );
}
