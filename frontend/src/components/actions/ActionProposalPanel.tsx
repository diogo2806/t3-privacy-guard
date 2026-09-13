import { Bot, ExternalLink, KeyRound } from 'lucide-react';
import type { ActionProposal } from '../../services/privacyGuardApi';
import { SectionHeader } from '../ui/SectionHeader';
import { Surface } from '../ui/Surface';

interface Props { actions: ActionProposal[]; selectedActionId: string | null; onSelect: (action: ActionProposal) => void; }

export function ActionProposalPanel({ actions, selectedActionId, onSelect }: Props) {
  return (
    <Surface>
      <SectionHeader eyebrow="Agent proposals" title="Requested actions" icon={<Bot aria-hidden="true" />} />
      {actions.length === 0 ? <p className="empty-copy">No agent action has been proposed yet.</p> : (
        <div className="action-list">
          {actions.map((action) => (
            <button key={action.id} type="button" className={`action-row ${selectedActionId === action.id ? 'action-row-selected' : ''}`} onClick={() => onSelect(action)}>
              <span className="action-row-icon">{action.host === 'attacker.example' ? <ExternalLink aria-hidden="true" /> : <KeyRound aria-hidden="true" />}</span>
              <span className="action-row-main"><strong>{action.action}</strong><small>{action.host ?? 'No outbound host'}</small></span>
              <span className="action-row-status">{action.status}</span>
            </button>
          ))}
        </div>
      )}
    </Surface>
  );
}
