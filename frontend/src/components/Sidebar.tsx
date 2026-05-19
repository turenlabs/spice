import { FileWarning, HardDrive, PackageSearch, Settings2, ShieldCheck } from 'lucide-react';
import type { Mode } from '../types';
import spiceLogo from '../assets/spice-logo.png';

export function Sidebar({ mode, onModeChange }: {
  mode: Mode;
  onModeChange: (mode: Mode) => void;
}) {
  return (
    <aside className="side">
      <button className="side-logo" type="button" onClick={() => onModeChange('scan')} aria-label="Spice">
        <img src={spiceLogo} alt="" />
      </button>
      <nav className="side-nav" aria-label="Primary">
        <button className="side-btn" data-active={mode === 'scan'} type="button" onClick={() => onModeChange('scan')} aria-label="Scan">
          <HardDrive size={20} />
          <span className="side-tip">Scan</span>
        </button>
        <button className="side-btn" data-active={mode === 'findings'} type="button" onClick={() => onModeChange('findings')} aria-label="Triage evidence">
          <FileWarning size={20} />
          <span className="side-tip">Evidence</span>
        </button>
        <button className="side-btn" data-active={mode === 'inventory'} type="button" onClick={() => onModeChange('inventory')} aria-label="Inventory">
          <PackageSearch size={20} />
          <span className="side-tip">Inventory</span>
        </button>
        <button className="side-btn" data-active={mode === 'harden'} type="button" onClick={() => onModeChange('harden')} aria-label="Harden">
          <ShieldCheck size={20} />
          <span className="side-tip">Harden</span>
        </button>
        <div className="side-spacer" />
        <button className="side-btn" data-active={mode === 'settings'} type="button" onClick={() => onModeChange('settings')} aria-label="Settings">
          <Settings2 size={20} />
          <span className="side-tip">Settings</span>
        </button>
      </nav>
    </aside>
  );
}
