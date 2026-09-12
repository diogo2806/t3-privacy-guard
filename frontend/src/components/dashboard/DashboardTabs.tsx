export type DashboardView = 'demo' | 'evidence';

interface Props { active: DashboardView; onChange: (view: DashboardView) => void; }

export function DashboardTabs({ active, onChange }: Props) {
  return (
    <nav className="dashboard-tabs" aria-label="Dashboard views">
      <button type="button" className={active === 'demo' ? 'dashboard-tab dashboard-tab-active' : 'dashboard-tab'} aria-current={active === 'demo' ? 'page' : undefined} onClick={() => onChange('demo')}>Demo</button>
      <button type="button" className={active === 'evidence' ? 'dashboard-tab dashboard-tab-active' : 'dashboard-tab'} aria-current={active === 'evidence' ? 'page' : undefined} onClick={() => onChange('evidence')}>Evidence</button>
    </nav>
  );
}
