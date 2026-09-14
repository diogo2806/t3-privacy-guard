export type DashboardView = 'demo' | 'presentation' | 'evidence';

interface Props { active: DashboardView; onChange: (view: DashboardView) => void; }

function tabClass(active: boolean): string {
  return active ? 'dashboard-tab dashboard-tab-active' : 'dashboard-tab';
}

export function DashboardTabs({ active, onChange }: Props) {
  return (
    <nav className="dashboard-tabs" aria-label="Product areas">
      <button type="button" className={tabClass(active === 'demo')} aria-current={active === 'demo' ? 'page' : undefined} onClick={() => onChange('demo')}>Protection flow</button>
      <button type="button" className={tabClass(active === 'presentation')} aria-current={active === 'presentation' ? 'page' : undefined} onClick={() => onChange('presentation')}>Executive demo</button>
      <button type="button" className={tabClass(active === 'evidence')} aria-current={active === 'evidence' ? 'page' : undefined} onClick={() => onChange('evidence')}>Evidence</button>
    </nav>
  );
}
