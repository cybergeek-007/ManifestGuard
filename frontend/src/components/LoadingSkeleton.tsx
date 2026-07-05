interface LoadingSkeletonProps {
  variant: 'table' | 'detail' | 'summary' | 'card';
}

export default function LoadingSkeleton({ variant }: LoadingSkeletonProps) {
  if (variant === 'summary') {
    return (
      <div className="scan-summary">
        {[1, 2, 3, 4].map(i => (
          <div key={i} className="summary-stat">
            <div className="skeleton skeleton-text short" />
            <div className="skeleton skeleton-heading" />
          </div>
        ))}
      </div>
    );
  }

  if (variant === 'table') {
    return (
      <div className="inventory-panel">
        <div className="skeleton skeleton-text" style={{ width: '100%', height: 40, marginBottom: 16 }} />
        {[1, 2, 3, 4, 5].map(i => (
          <div key={i} className="skeleton skeleton-row" />
        ))}
      </div>
    );
  }

  if (variant === 'detail') {
    return (
      <div className="detail-panel">
        <div className="skeleton skeleton-heading" />
        <div className="skeleton skeleton-text" />
        <div className="skeleton skeleton-text medium" />
        <div className="skeleton skeleton-card" />
        <div className="skeleton skeleton-text" />
        <div className="skeleton skeleton-text short" />
      </div>
    );
  }

  return <div className="skeleton skeleton-card" />;
}
