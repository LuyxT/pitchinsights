export default function LoadingState({ rows = 4 }) {
  return (
    <div className="loading">
      {Array.from({ length: rows }).map((_, idx) => (
        <div key={idx} className="skeleton" style={{ width: `${80 - idx * 5}%` }} />
      ))}
    </div>
  );
}
