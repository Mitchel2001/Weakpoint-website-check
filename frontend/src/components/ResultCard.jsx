const STATUS_LABELS = {
  pass: 'OK',
  warn: 'Let op',
  fail: 'Blokkerend',
  info: 'Info'
};

const hasData = (value) =>
  value && typeof value === 'object' && Object.keys(value).length > 0;

export default function ResultCard({ item }) {
  const { title, summary, impact, remediation, status, details } = item;

  const renderDetailsContent = () => {
    if (item.id === 'owasp_top10_quickscan' && Array.isArray(details?.owasp_top10)) {
      return (
        <div className="owasp-quickscan">
          <ul className="owasp-quickscan__list">
            {details.owasp_top10.map((category) => (
              <li key={category.id} className={`owasp-quickscan__row status-${category.status}`}>
                <div className="owasp-quickscan__head">
                  <span className="owasp-quickscan__code">{category.id}</span>
                  <strong>{category.title}</strong>
                  <span className="status-pill">{STATUS_LABELS[category.status] ?? category.status}</span>
                </div>
                <p className="owasp-quickscan__summary">{category.summary}</p>
                {hasData(category.evidence) && (
                  <details>
                    <summary>Bewijs</summary>
                    <pre>{JSON.stringify(category.evidence, null, 2)}</pre>
                  </details>
                )}
              </li>
            ))}
          </ul>
          {typeof details.extra_requests === 'number' && (
            <p className="owasp-quickscan__meta">
              Extra HTTP-verzoeken tijdens quickscan: {details.extra_requests}
            </p>
          )}
        </div>
      );
    }

    return <pre>{JSON.stringify(details, null, 2)}</pre>;
  };

  return (
    <article className={`result-card status-${status}`}>
      <header>
        <h3>{title}</h3>
        <span className="status-pill">{STATUS_LABELS[status] ?? status}</span>
      </header>
      <p className="summary">{summary}</p>
      {impact && (
        <p className="impact">
          <span>Impact:</span> {impact}
        </p>
      )}
      <p className="remediation">
        <span>Advies:</span> {remediation}
      </p>
      {details && Object.keys(details).length > 0 && (
        <details>
          <summary>Details</summary>
          {renderDetailsContent()}
        </details>
      )}
    </article>
  );
}
