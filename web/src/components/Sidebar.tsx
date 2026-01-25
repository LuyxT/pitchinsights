const navItems = [
  { id: "home", label: "Home", path: "/", icon: "iconoir-home" },
  { id: "trainings", label: "Trainingsplanung", path: "/training", icon: "iconoir-calendar" },
  { id: "players", label: "Spieler:innen", path: "/players", icon: "iconoir-group" },
  { id: "calendar", label: "Kalender", path: "/calendar", icon: "iconoir-calendar" },
  { id: "messages", label: "Nachrichten", path: "/messages", icon: "iconoir-message" },
  { id: "polls", label: "Abstimmungen", path: "/polls", icon: "iconoir-task-list" },
  { id: "settings", label: "Einstellungen", path: "/settings", icon: "iconoir-settings" },
];

export default function Sidebar({ currentPath, onNavigate }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-title">Fc PitchInsights</div>
      <nav className="sidebar-nav">
        {navItems.map((item) => (
          <button
            key={item.id}
            className={`app-item${currentPath === item.path ? " active" : ""}`}
            onClick={() => onNavigate(item.path)}
          >
            <span className={item.icon} />
            <span>{item.label}</span>
          </button>
        ))}
      </nav>
    </aside>
  );
}
