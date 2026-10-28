export type DashboardView = 'demo' | 'presentation' | 'policy';

interface Props { active: DashboardView; onChange: (view: DashboardView) => void; showPolicy?: boolean; }

function tabClass(active: boolean): string {
  return active ? 'dashboard-tab dashboard-tab-active' : 'dashboard-tab';
}

export function DashboardTabs({ active, onChange, showPolicy = false }: Props) {
  return (
    <nav className="dashboard-tabs" aria-label="Product areas">
      <button type="button" className={tabClass(active === 'demo')} aria-current={active === 'demo' ? 'page' : undefined} onClick={() => onChange('demo')}>Protection flow</button>
      <button type="button" className={tabClass(active === 'presentation')} aria-current={active === 'presentation' ? 'page' : undefined} onClick={() => onChange('presentation')}>Executive demo</button>
      {showPolicy && <button type="button" className={tabClass(active === 'policy')} aria-current={active === 'policy' ? 'page' : undefined} onClick={() => onChange('policy')}>Policy</button>}
    </nav>
  );
}
