export type PillState = 'ok' | 'off' | 'pending';

interface Props {
  state: PillState;
  label: string;
}

export function StatusPill({ state, label }: Props) {
  return <span className={`status-pill status-pill-${state}`}>{label}</span>;
}
