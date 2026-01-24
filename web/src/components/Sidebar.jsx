const navItems = [
  { id: "dashboard", label: "Dashboard", path: "/" },
  { id: "trainings", label: "Trainingsplanung", path: "/training" },
  { id: "players", label: "Spieler:innen", path: "/players" },
  { id: "calendar", label: "Kalender", path: "/calendar" },
  { id: "messages", label: "Nachrichten", path: "/messages" },
  { id: "polls", label: "Abstimmungen", path: "/polls" },
  { id: "settings", label: "Einstellungen", path: "/settings" },
];

export default function Sidebar({ currentPath, onNavigate }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-title">Pitch Insights</div>
      <nav className="sidebar-nav">
        {navItems.map((item) => (
          <button
            key={item.id}
            className={`nav-item${currentPath === item.path ? " active" : ""}`}
            onClick={() => onNavigate(item.path)}
          >
            <span>{item.label}</span>
          </button>
        ))}
      </nav>
    </aside>
  );
}
