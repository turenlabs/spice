import { CheckCircle2, Info, RotateCw, ShieldCheck, Terminal, TriangleAlert } from 'lucide-react';
import { Button, Spinner } from './Common';
import type { ReactNode } from 'react';
import type { GuardrailSetting, HardenStatus, PackageManagerStatus } from '../types';

export function HardenPanel({
  applying,
  refreshing,
  selectedPreset,
  status,
  onApply,
  onRefresh,
  onSelectPreset,
}: {
  applying: boolean;
  refreshing: boolean;
  selectedPreset: string;
  status: HardenStatus | null;
  onApply: () => void;
  onRefresh: () => void;
  onSelectPreset: (preset: string) => void;
}) {
  const npm = status?.npm;
  const selected = status?.presets.find((preset) => preset.id === selectedPreset) ?? status?.presets[0];

  return (
    <section className="hardenPage">
      <div className="hardenHero">
        <div>
          <span className="eyebrow">PACKAGE GUARDRAILS</span>
          <h1>Harden installs before the next package lands</h1>
          <p>
            Apply simple npm defaults that slow down brand-new releases, pin new installs, and avoid Git dependency shortcuts.
            Python is advisory here because stock pip does not have a global rolling package-age setting.
          </p>
        </div>
        <div className="hardenHeroActions">
          <Button disabled={refreshing} icon={refreshing ? <Spinner /> : <RotateCw size={16} />} onClick={onRefresh} variant="secondary">Refresh</Button>
          <Button disabled={applying || refreshing || !npm?.available || !selected} icon={applying ? <Spinner /> : <ShieldCheck size={16} />} onClick={onApply} variant="primary">
            Apply preset
          </Button>
        </div>
      </div>

      <div className="hardenGrid">
        <section className="hardenCard hardenWide">
          <div className="hardenCardHead">
            <div>
              <h2>npm guardrails</h2>
              <p>{npm?.available ? `npm ${npm.version || ''}`.trim() : 'npm was not found from the app environment.'}</p>
            </div>
            <StatusPill value={npm?.activePreset || 'unknown'} />
          </div>
          {refreshing && !status && <div className="hardenNotice"><Spinner /> Reading local package manager settings</div>}

          <div className="hardenPresetGrid" role="radiogroup" aria-label="npm hardening preset">
            {(status?.presets ?? []).map((preset) => (
              <button
                aria-checked={selectedPreset === preset.id}
                className="hardenPreset"
                data-active={selectedPreset === preset.id}
                key={preset.id}
                onClick={() => onSelectPreset(preset.id)}
                role="radio"
                type="button"
              >
                <span className="hardenRadio" />
                <strong>{preset.name}</strong>
                <em>{preset.description}</em>
              </button>
            ))}
          </div>

          {selected && (
            <div className="hardenCommandBox">
              <span className="eyebrow">COMMANDS SPICE WILL RUN</span>
              <code>
                {selected.settings.map((setting) => (
                  setting.wanted === 'null'
                    ? `npm config delete ${setting.key} --location=user`
                    : `npm config set ${setting.key} ${setting.wanted} --location=user`
                )).join('\n')}
              </code>
            </div>
          )}

          <SettingsTable settings={npm?.settings ?? []} />
          {npm?.error && <div className="hardenNotice danger"><TriangleAlert size={16} />{npm.error}</div>}
        </section>

        <PackageManagerCard
          icon={<Terminal size={18} />}
          status={status?.python ?? null}
          title="Python guardrails"
        />

        <section className="hardenCard">
          <div className="hardenCardHead">
            <div>
              <h2>How to use this</h2>
              <p>Keep this advisory and reversible.</p>
            </div>
            <Info size={18} />
          </div>
          <ul className="hardenList">
            <li>Use <b>Recommended</b> for daily npm work.</li>
            <li>Use <b>Strict</b> on high-risk machines or before incident response scans.</li>
            <li>Use <b>npm defaults</b> if a project breaks and you need to back out quickly.</li>
            <li>For CI, prefer frozen lockfile installs such as <code>npm ci</code>.</li>
          </ul>
        </section>
      </div>
    </section>
  );
}

function SettingsTable({ settings }: { settings: GuardrailSetting[] }) {
  return (
    <div className="hardenSettings">
      {settings.map((setting) => (
        <div className="hardenSetting" data-status={setting.status} key={setting.key}>
          {setting.status === 'ok' ? <CheckCircle2 size={16} /> : <TriangleAlert size={16} />}
          <div>
            <strong>{setting.key}</strong>
            <span>{setting.description}</span>
          </div>
          <code>{setting.value || 'not set'}</code>
        </div>
      ))}
    </div>
  );
}

function PackageManagerCard({ icon, status, title }: {
  icon: ReactNode;
  status: PackageManagerStatus | null;
  title: string;
}) {
  return (
    <section className="hardenCard">
      <div className="hardenCardHead">
        <div>
          <h2>{title}</h2>
          <p>{status?.available ? status.version : 'Advisory checks only'}</p>
        </div>
        {icon}
      </div>
      <SettingsTable settings={status?.settings ?? []} />
      <ul className="hardenList">
        {(status?.notes ?? []).map((note) => <li key={note}>{note}</li>)}
      </ul>
    </section>
  );
}

function StatusPill({ value }: { value: string }) {
  const label = value === 'custom' ? 'Custom settings' : value === 'defaults' ? 'npm defaults' : value;
  return <span className="hardenStatusPill">{label}</span>;
}
