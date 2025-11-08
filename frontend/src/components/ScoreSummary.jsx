import PropTypes from 'prop-types';

const STATUS_ORDER = ['pass', 'warn', 'fail', 'info'];
const STATUS_LABELS = {
  pass: 'OK',
  warn: 'Waarschuwing',
  fail: 'Blokkade',
  info: 'Info'
};

export default function ScoreSummary({ score, sections, sectionStats }) {
  if (!score || !sections || !sectionStats) {
    return null;
  }

  const gaugeValue = Math.max(0, Math.min(score.overall ?? 0, 100));
  const circleStyle = {
    '--score-value': `${gaugeValue}%`
  };

  return (
    <div className="score-summary">
      <div className="score-overall">
        <div className="score-circle" style={circleStyle}>
          <div className="score-circle-inner">
            <span className="score-number">{gaugeValue}</span>
            <span className="score-suffix">/100</span>
          </div>
        </div>
        <div>
          <p className="score-grade">Beveiligingsscore {score.grade}</p>
          <p className="score-label">{score.label}</p>
          <p className="muted score-description">
            Gebaseerd op {score.status_counts?.total ?? 0} checks verdeeld over kritieke, belangrijke en aanvullende categorieën.
          </p>
        </div>
      </div>

      <div className="score-distribution">
        {sections.map((section) => {
          const stats = sectionStats[section.key];
          const sectionScore = score.sections?.[section.key];
          if (!stats || !sectionScore) {
            return null;
          }
          const total = stats.total || 1;
          return (
            <div key={section.key} className="score-row">
              <div className="score-row-header">
                <p className="label">{section.title}</p>
                <span className="score-row-value">{sectionScore.percentage}%</span>
              </div>
              <div className="score-bar" aria-hidden="true">
                {STATUS_ORDER.map((status) => {
                  const value = stats[status] || 0;
                  if (!value) {
                    return null;
                  }
                  const width = (value / total) * 100;
                  return (
                    <span
                      key={`${section.key}-${status}`}
                      className={`score-bar-segment status-${status}`}
                      style={{ width: `${width}%` }}
                      title={`${value} ${STATUS_LABELS[status]}`}
                    />
                  );
                })}
              </div>
              <p className="muted score-row-footer">
                {stats.pass} OK · {stats.warn} waarschuwingen · {stats.fail} blokkades · {stats.info} info
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}

ScoreSummary.propTypes = {
  score: PropTypes.shape({
    overall: PropTypes.number,
    grade: PropTypes.string,
    label: PropTypes.string,
    sections: PropTypes.object,
    status_counts: PropTypes.object
  }),
  sections: PropTypes.arrayOf(
    PropTypes.shape({
      key: PropTypes.string.isRequired,
      title: PropTypes.string.isRequired
    })
  ),
  sectionStats: PropTypes.object
};
