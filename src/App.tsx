import { useEffect, useState } from 'react';
import type { CAPolicy } from './model/types';
import { AnalysisView } from './ui/AnalysisView';
import { ExportView } from './ui/ExportView';
import { PolicyList } from './ui/PolicyList';
import { PolicyWizard } from './ui/PolicyWizard';
import { TenantSetup } from './ui/TenantSetup';
import { clearState, loadState, saveState, STEPS, stepByIndex, stepIndex, type AppState } from './ui/state';

export default function App() {
  const [state, setState] = useState<AppState>(() => loadState());
  const [editing, setEditing] = useState<CAPolicy | null>(null);
  const [wizardDirty, setWizardDirty] = useState(false);
  const [tenantSetupKey, setTenantSetupKey] = useState(0);

  useEffect(() => {
    saveState(state);
  }, [state]);

  useEffect(() => {
    if (editing) window.scrollTo(0, 0);
  }, [editing]);

  const idx = stepIndex(state.step);

  function leaveWizard(): boolean {
    if (!editing || !wizardDirty) return true;
    return window.confirm('Discard unsaved policy changes?');
  }

  function go(step: AppState['step']) {
    if (!leaveWizard()) return;
    setWizardDirty(false);
    setEditing(null);
    setState({ ...state, step });
    window.scrollTo(0, 0);
  }

  const narrow = state.step !== 'analysis';

  return (
    <div className="app">
      <div className="chrome">
        <header className="app-header">
          <div className="shell">
            <div className="brand">
              <img className="mark" src={`${import.meta.env.BASE_URL}logo.png`} alt="" />
              <div>
                <h1>CA Gap Evaluator</h1>
                <p>Conditional Access coverage, analyzed locally.</p>
              </div>
            </div>
            <button
              type="button"
              className="link"
              onClick={() => {
                if (window.confirm('Clear all policies and tenant setup from this browser?')) {
                  clearState();
                  setEditing(null);
                  setWizardDirty(false);
                  setTenantSetupKey((k) => k + 1);
                  setState(loadState());
                }
              }}
            >
              Clear all data
            </button>
          </div>
        </header>
        <nav className="stepper" aria-label="Steps">
          <div className="shell stepper-track">
            {STEPS.map((s) => (
              <button
                type="button"
                key={s.id}
                className={s.id === state.step ? 'current' : ''}
                onClick={() => go(s.id)}
              >
                {s.index + 1}. {s.label}
              </button>
            ))}
          </div>
        </nav>
      </div>
      <main className="page">
        <div className={narrow ? 'page-narrow' : undefined}>
          {state.step === 'tenant' && (
            <TenantSetup
              key={tenantSetupKey}
              tenant={state.tenant}
              onChange={(tenant) => setState({ ...state, tenant })}
            />
          )}
          {state.step === 'policies' && !editing && (
            <PolicyList
              policies={state.policies}
              onPolicies={(policies) => setState({ ...state, policies })}
              onTenant={(tenant) => setState({ ...state, tenant })}
              onEdit={setEditing}
            />
          )}
          {state.step === 'policies' && editing && (
            <PolicyWizard
              policy={editing}
              onDirtyChange={setWizardDirty}
            onCancel={() => {
              setWizardDirty(false);
              setEditing(null);
              window.scrollTo(0, 0);
            }}
            onSave={(policy) => {
              const exists = state.policies.some((p) => p.id === policy.id);
              const policies = exists
                ? state.policies.map((p) => (p.id === policy.id ? policy : p))
                : [...state.policies, policy];
              setState({ ...state, policies });
              setEditing(null);
              window.scrollTo(0, 0);
            }}
            />
          )}
          {state.step === 'analysis' && (
            <AnalysisView policies={state.policies} tenant={state.tenant} />
          )}
          {state.step === 'export' && (
            <ExportView policies={state.policies} tenant={state.tenant} />
          )}
        </div>
        {!editing && (
          <div className={`footer-nav${narrow ? ' footer-nav-narrow' : ''}`}>
            <button
              type="button"
              className="btn secondary"
              disabled={idx === 0}
              onClick={() => go(stepByIndex(idx - 1))}
            >
              Back
            </button>
            <button
              type="button"
              className="btn"
              disabled={idx === STEPS.length - 1}
              onClick={() => go(stepByIndex(idx + 1))}
            >
              Next
            </button>
          </div>
        )}
      </main>
    </div>
  );
}
