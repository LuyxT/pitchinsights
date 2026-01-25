export default function LoadingState({ rows = 4, title, description }) {
  return (
    <div className="loading">
      {title ? <div className="page-title">{title}</div> : null}
      {description ? <div className="page-subtitle">{description}</div> : null}
      {Array.from({ length: rows }).map((_, idx) => (
        <div key={idx} className="skeleton" style={{ width: `${80 - idx * 5}%` }} />
      ))}
    </div>
  );
}
