export default function Table({ columns = [], rows = [] }) {
  return (
    <div className="table">
      <div className="table-head">
        {columns.map((col) => (
          <div key={col.key} className="table-cell header">{col.label}</div>
        ))}
      </div>
      {rows.map((row, idx) => (
        <div key={row.id ?? idx} className="table-row">
          {columns.map((col) => (
            <div key={col.key} className="table-cell">{row[col.key]}</div>
          ))}
        </div>
      ))}
    </div>
  );
}
