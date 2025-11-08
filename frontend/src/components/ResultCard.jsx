const STATUS_LABELS = {
  pass: 'OK',
  warn: 'Let op',
  fail: 'Blokkerend',
  info: 'Info'
};

export default function ResultCard({ item }) {
  const { title, summary, remediation, status, details } = item;
  return (
    <article className={`result-card status-${status}`}>
      <header>
        <h3>{title}</h3>
        <span className="status-pill">{STATUS_LABELS[status] ?? status}</span>
      </header>
      <p className="summary">{summary}</p>
      <p className="remediation">
        <span>Advies:</span> {remediation}
      </p>
      {details && Object.keys(details).length > 0 && (
        <details>
          <summary>Details</summary>
          <pre>{JSON.stringify(details, null, 2)}</pre>
        </details>
      )}
    </article>
  );
}
