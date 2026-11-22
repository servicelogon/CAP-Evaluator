import { useEffect, useRef, useState } from 'react';
import type { CAPolicy } from './model/types';
import { AnalysisView } from './ui/AnalysisView';
import { ExportView } from './ui/ExportView';
import { PolicyList } from './ui/PolicyList';
import { PolicyWizard } from './ui/PolicyWizard';
import { SiteFooter, SiteHeader } from './ui/SiteChrome';
import { TenantSetup } from './ui/TenantSetup';
import { clearState, loadState, saveState, STEPS, stepIndex, type AppState } from './ui/state';

const SHORT_STEP: Record<AppState['step'], string> = {
  tenant: 'Tenant',
  policies: 'Policies',
  analysis: 'Analysis',
  export: 'Export',
};

export default function App() {
  const [state, setState] = useState<AppState>(() => loadState());
  const [editing, setEditing] = useState<CAPolicy | null>(null);
  const [wizardDirty, setWizardDirty] = useState(false);
  const [tenantSetupKey, setTenantSetupKey] = useState(0);
  const mainRef = useRef<HTMLElement>(null);
  const stepperRef = useRef<HTMLElement>(null);

  useEffect(() => {
    saveState(state);
  }, [state]);

  // Bring the step heading up under the sticky stepper, but only when the
  // reader has scrolled past it. At the top of the page nothing moves.
  function revealStep() {
    const main = mainRef.current;
    if (!main || typeof window.scrollTo !== 'function') return;
    const offset = stepperRef.current?.offsetHeight ?? 0;
    const top = main.getBoundingClientRect().top + window.scrollY - offset;
    if (window.scrollY > top) {
      try {
        window.scrollTo({ top, behavior: 'auto' });
      } catch {
        /* jsdom has no scrolling */
      }
    }
  }

  useEffect(() => {
    if (editing) revealStep();
  }, [editing]);

  // Sticky headings below the stepper (the heat map columns on phones) need its height.
  useEffect(() => {
    const el = stepperRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const set = () => document.documentElement.style.setProperty('--stepper-h', `${el.offsetHeight}px`);
    set();
    const observer = new ResizeObserver(set);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const idx = stepIndex(state.step);

  function leaveWizard(): boolean {
    if (!editing || !wizardDirty) return true;
    return window.confirm('Discard unsaved policy changes?');
  }

  function go(step: AppState['step']) {
    if (!leaveWizard()) return;
    setWizardDirty(false);
    setEditing(null);
    setState((s) => ({ ...s, step }));
    requestAnimationFrame(revealStep);
  }

  const wide = state.step === 'analysis';
  const prev = idx > 0 ? STEPS[idx - 1] : null;
  const next = idx < STEPS.length - 1 ? STEPS[idx + 1] : null;

  return (
    <div className="app">
      <a className="skip" href="#main">Skip to content</a>
      <SiteHeader />
      <section className="tool-intro shell" aria-labelledby="tool-title">
        <div className="tool-intro-row">
          <p className="kicker">Toolbox</p>
          <button
            type="button"
            className="text-btn clear-data"
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
        <h1 id="tool-title">CA Gap Evaluator</h1>
        <p className="opening-line">Conditional Access coverage, analyzed locally. Your policies never leave this browser.</p>
      </section>
      <nav className="stepper" aria-label="Steps" ref={stepperRef}>
        <ol className="shell stepper-track">
          {STEPS.map((s) => {
            const status = s.index === idx ? 'current' : s.index < idx ? 'done' : 'todo';
            return (
              <li key={s.id} className={status}>
                <button
                  type="button"
                  aria-current={status === 'current' ? 'step' : undefined}
                  aria-label={`${s.index + 1}. ${s.label}`}
                  onClick={() => go(s.id)}
                >
                  <span className="step-num" aria-hidden="true">0{s.index + 1}</span>
                  <span className="step-label step-label-full" aria-hidden="true">{s.label}</span>
                  <span className="step-label step-label-short" aria-hidden="true">{SHORT_STEP[s.id]}</span>
                </button>
              </li>
            );
          })}
        </ol>
      </nav>
      <main id="main" tabIndex={-1} className={`page shell${wide ? ' page-wide' : ''}`} ref={mainRef}>
        <div className="page-body" key={editing ? 'wizard' : state.step}>
          {state.step === 'tenant' && (
            <TenantSetup
              key={tenantSetupKey}
              tenant={state.tenant}
              onChange={(tenant) => setState((s) => ({ ...s, tenant }))}
            />
          )}
          {state.step === 'policies' && !editing && (
            <PolicyList
              policies={state.policies}
              onPolicies={(policies) => setState((s) => ({ ...s, policies }))}
              onTenant={(tenant) => setState((s) => ({ ...s, tenant }))}
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
                requestAnimationFrame(revealStep);
              }}
              onSave={(policy) => {
                setState((s) => {
                  const exists = s.policies.some((p) => p.id === policy.id);
                  const policies = exists
                    ? s.policies.map((p) => (p.id === policy.id ? policy : p))
                    : [...s.policies, policy];
                  return { ...s, policies };
                });
                setEditing(null);
                requestAnimationFrame(revealStep);
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
          <nav className="pager" aria-label="Step navigation">
            {prev ? (
              <button type="button" className="pager-link pager-prev" aria-label={`Back: ${prev.label}`} onClick={() => go(prev.id)}>
                <span className="pager-kicker"><span className="arrow-icon arrow-back" aria-hidden="true" />Back</span>
                <span className="pager-title">{prev.label}</span>
              </button>
            ) : <span />}
            {next && (
              <button type="button" className="pager-link pager-next" aria-label={`Next: ${next.label}`} onClick={() => go(next.id)}>
                <span className="pager-kicker">Next</span>
                <span className="pager-title">{next.label}<span className="arrow-icon" aria-hidden="true" /></span>
              </button>
            )}
          </nav>
        )}
      </main>
      <SiteFooter />
    </div>
  );
}
