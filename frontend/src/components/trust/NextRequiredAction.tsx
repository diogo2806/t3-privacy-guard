import { ArrowRight, ShieldCheck } from 'lucide-react';
import { Button } from '../ui/Button';
import { Surface } from '../ui/Surface';

interface Props {
  busy: boolean;
  onPrepareSafePath: () => void;
}

export function NextRequiredAction({ busy, onPrepareSafePath }: Props) {
  return (
    <Surface className="next-required-action" aria-labelledby="next-required-action-title">
      <div>
        <p className="eyebrow">Try the safe path</p>
        <h2 id="next-required-action-title">Prepare a minimum-scope credential revocation</h2>
        <p>This only creates and evaluates a constrained remediation proposal. It does not authorize or execute the protected action.</p>
      </div>
      <Button variant="primary" onClick={onPrepareSafePath} disabled={busy}><ShieldCheck aria-hidden="true" />Prepare safe path<ArrowRight aria-hidden="true" /></Button>
    </Surface>
  );
}
