import { useMemo, useState } from 'react';
import { APP_CATALOG, KEYWORD, USER_ACTION } from '../catalog/apps';
import { AUTH_STRENGTH } from '../catalog/authStrengths';
import { EXTENDED_ROLES, PRIVILEGED_ROLES } from '../catalog/roles';
import type { CAPolicy, PolicyState } from '../model/types';
import { ALL_GUEST_TYPES, linesOf } from './labels';

const SECTIONS = ['Name', 'Users', 'Target resources', 'Network', 'Conditions', 'Grant', 'Session'] as const;
type Section = (typeof SECTIONS)[number];

const CLIENT_TYPES = [
  { id: 'all', label: 'All clients' },
  { id: 'browser', label: 'Browser' },
  { id: 'mobileAppsAndDesktopClients', label: 'Mobile apps and desktop clients' },
  { id: 'exchangeActiveSync', label: 'Exchange ActiveSync' },
  { id: 'other', label: 'Other (legacy)' },
];

const BUILTIN = [
  { id: 'block', label: 'Block access' },
  { id: 'mfa', label: 'Require MFA' },
  { id: 'compliantDevice', label: 'Require compliant device' },
  { id: 'domainJoinedDevice', label: 'Require hybrid Azure AD joined device' },
  { id: 'compliantApplication', label: 'Require app protection policy' },
  { id: 'passwordChange', label: 'Require password change' },
  { id: 'approvedApplication', label: 'Require approved client app (retired)' },
];

interface Props {
  policy: CAPolicy;
  onSave: (policy: CAPolicy) => void;
  onCancel: () => void;
}

function includeMode(apps: string[]): 'All' | 'Office365' | 'MicrosoftAdminPortals' | 'selected' {
  if (apps.length === 1 && apps[0] === KEYWORD.all) return 'All';
  if (apps.length === 1 && apps[0] === KEYWORD.office365) return 'Office365';
  if (apps.length === 1 && apps[0] === KEYWORD.adminPortals) return 'MicrosoftAdminPortals';
  return 'selected';
}

export function PolicyWizard({ policy, onSave, onCancel }: Props) {
  const [draft, setDraft] = useState<CAPolicy>(() => structuredClone(policy));
  const [section, setSection] = useState<Section>('Name');
  const [appQuery, setAppQuery] = useState('');
  const [customApp, setCustomApp] = useState('');

  const users = draft.conditions.users;
  const apps = draft.conditions.applications;
  const grant = draft.grantControls ?? { operator: 'OR' as const, builtInControls: [], customAuthenticationFactors: [], termsOfUse: [], authenticationStrength: null };
  const session = draft.sessionControls;
  const mode = includeMode(apps.includeApplications);

  const filteredApps = useMemo(() => {
    const q = appQuery.trim().toLowerCase();
    return APP_CATALOG.filter((a) =>
      !q
      || a.name.toLowerCase().includes(q)
      || a.appId.includes(q)
      || a.aliases.some((x) => x.toLowerCase().includes(q)),
    );
  }, [appQuery]);

  function setUsers(patch: Partial<typeof users>) {
    setDraft({ ...draft, conditions: { ...draft.conditions, users: { ...users, ...patch } } });
  }
  function setApps(patch: Partial<typeof apps>) {
    setDraft({ ...draft, conditions: { ...draft.conditions, applications: { ...apps, ...patch } } });
  }
  function setGrant(next: typeof grant) {
    setDraft({ ...draft, grantControls: next });
  }

  const guestOn = !!users.includeGuestsOrExternalUsers;

  return (
    <div className="wizard">
      <div className="wizard-nav">
        {SECTIONS.map((s) => (
          <button type="button" key={s} className={s === section ? 'current' : ''} onClick={() => setSection(s)}>
            {s}
          </button>
        ))}
      </div>

      {section === 'Name' && (
        <>
          <label className="field">
            Display name
            <input value={draft.displayName} onChange={(e) => setDraft({ ...draft, displayName: e.target.value })} />
          </label>
          <label className="field">
            State
            <select
              value={draft.state}
              onChange={(e) => setDraft({ ...draft, state: e.target.value as PolicyState })}
            >
              <option value="enabled">On</option>
              <option value="enabledForReportingButNotEnforced">Report-only</option>
              <option value="disabled">Off</option>
            </select>
          </label>
        </>
      )}

      {section === 'Users' && (
        <>
          <fieldset>
            <legend>Include users</legend>
            <label className="check">
              <input type="radio" name="incUsers" checked={users.includeUsers.includes('All')} onChange={() => setUsers({ includeUsers: ['All'] })} />
              All users
            </label>
            <label className="check">
              <input type="radio" name="incUsers" checked={users.includeUsers.includes('None') && users.includeUsers.length === 1} onChange={() => setUsers({ includeUsers: ['None'] })} />
              None
            </label>
            <label className="check">
              <input
                type="radio"
                name="incUsers"
                checked={!users.includeUsers.includes('All') && !users.includeUsers.includes('None')}
                onChange={() => setUsers({ includeUsers: users.includeUsers.filter((u) => u !== 'All' && u !== 'None') })}
              />
              Selected users
            </label>
            {!users.includeUsers.includes('All') && !users.includeUsers.includes('None') && (
              <label className="field">
                User object IDs
                <textarea rows={3} value={users.includeUsers.join('\n')} onChange={(e) => setUsers({ includeUsers: linesOf(e.target.value) })} />
              </label>
            )}
          </fieldset>
          <label className="field">
            Include groups
            <textarea rows={2} value={users.includeGroups.join('\n')} onChange={(e) => setUsers({ includeGroups: linesOf(e.target.value) })} />
          </label>
          <label className="field">
            Exclude users (break-glass)
            <textarea rows={2} value={users.excludeUsers.join('\n')} onChange={(e) => setUsers({ excludeUsers: linesOf(e.target.value) })} />
          </label>
          <h3>Directory roles</h3>
          {[...PRIVILEGED_ROLES, ...EXTENDED_ROLES].map((r) => (
            <label className="check" key={r.id}>
              <input
                type="checkbox"
                checked={users.includeRoles.includes(r.id)}
                onChange={(e) => {
                  const includeRoles = e.target.checked
                    ? [...users.includeRoles, r.id]
                    : users.includeRoles.filter((id) => id !== r.id);
                  setUsers({ includeRoles });
                }}
              />
              {r.name}
            </label>
          ))}
          <label className="check">
            <input
              type="checkbox"
              checked={guestOn}
              onChange={(e) => setUsers({
                includeGuestsOrExternalUsers: e.target.checked
                  ? { guestOrExternalUserTypes: [...ALL_GUEST_TYPES], externalTenants: { membershipKind: 'all' } }
                  : null,
              })}
            />
            Include all guests and external users
          </label>
        </>
      )}

      {section === 'Target resources' && (
        <>
          <fieldset>
            <legend>Include</legend>
            {([
              ['All', 'All resources'],
              ['Office365', 'Office 365'],
              ['MicrosoftAdminPortals', 'Microsoft Admin Portals'],
              ['selected', 'Selected apps'],
            ] as const).map(([id, label]) => (
              <label className="check" key={id}>
                <input
                  type="radio"
                  name="apps"
                  checked={mode === id}
                  onChange={() => {
                    if (id === 'selected') setApps({ includeApplications: [] });
                    else setApps({ includeApplications: [id === 'All' ? KEYWORD.all : id === 'Office365' ? KEYWORD.office365 : KEYWORD.adminPortals] });
                  }}
                />
                {label}
              </label>
            ))}
          </fieldset>
          {mode === 'MicrosoftAdminPortals' && (
            <p className="warn">
              Microsoft Admin Portals covers portal sign-in (Azure portal, Exchange admin center, M365 portal, Protection Center).
              It does not cover Microsoft Graph, the Intune API, or Azure Resource Manager calls those portals make.
            </p>
          )}
          {mode === 'selected' && (
            <>
              <input className="search" value={appQuery} onChange={(e) => setAppQuery(e.target.value)} placeholder="Search apps" aria-label="Search apps" />
              <div className="app-pick">
                {filteredApps.map((a) => (
                  <label className="check" key={a.appId}>
                    <input
                      type="checkbox"
                      checked={apps.includeApplications.includes(a.appId)}
                      onChange={(e) => {
                        const includeApplications = e.target.checked
                          ? [...apps.includeApplications, a.appId]
                          : apps.includeApplications.filter((id) => id !== a.appId);
                        setApps({ includeApplications });
                      }}
                    />
                    <span>
                      {a.name}
                      {a.groups.length > 0 && ` · ${a.groups.join(', ')}`}
                      {!a.targetable && <span className="app-note"> This is a client app and cannot be targeted.</span>}
                      {a.surface === 'graph' && !a.targetable && (
                        <span className="app-note"> Microsoft Graph can only be covered via All resources.</span>
                      )}
                      <span className="app-note">{a.appId}</span>
                    </span>
                  </label>
                ))}
              </div>
              <label className="field">
                Add app ID
                <input value={customApp} onChange={(e) => setCustomApp(e.target.value)} />
              </label>
              <button
                type="button"
                className="btn secondary"
                onClick={() => {
                  const id = customApp.trim();
                  if (!id) return;
                  if (!apps.includeApplications.includes(id)) setApps({ includeApplications: [...apps.includeApplications, id] });
                  setCustomApp('');
                }}
              >
                Add
              </button>
            </>
          )}
          <label className="check">
            <input
              type="checkbox"
              checked={apps.includeUserActions.includes(USER_ACTION.registerSecurityInfo)}
              onChange={(e) => setApps({
                includeUserActions: e.target.checked
                  ? [...apps.includeUserActions, USER_ACTION.registerSecurityInfo]
                  : apps.includeUserActions.filter((x) => x !== USER_ACTION.registerSecurityInfo),
              })}
            />
            User action: Register security information
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={apps.includeUserActions.includes(USER_ACTION.registerDevice)}
              onChange={(e) => setApps({
                includeUserActions: e.target.checked
                  ? [...apps.includeUserActions, USER_ACTION.registerDevice]
                  : apps.includeUserActions.filter((x) => x !== USER_ACTION.registerDevice),
              })}
            />
            User action: Register or join devices
          </label>
          <label className="field">
            Exclude applications (IDs or Office365 / MicrosoftAdminPortals)
            <textarea rows={3} value={apps.excludeApplications.join('\n')} onChange={(e) => setApps({ excludeApplications: linesOf(e.target.value) })} />
          </label>
        </>
      )}

      {section === 'Network' && (
        <fieldset>
          <legend>Locations</legend>
          <label className="check">
            <input
              type="radio"
              name="loc"
              checked={!draft.conditions.locations}
              onChange={() => setDraft({ ...draft, conditions: { ...draft.conditions, locations: null } })}
            />
            Not configured (any network)
          </label>
          <label className="check">
            <input
              type="radio"
              name="loc"
              checked={!!draft.conditions.locations && draft.conditions.locations.excludeLocations.length === 0}
              onChange={() => setDraft({ ...draft, conditions: { ...draft.conditions, locations: { includeLocations: ['All'], excludeLocations: [] } } })}
            />
            All locations
          </label>
          <label className="check">
            <input
              type="radio"
              name="loc"
              checked={!!draft.conditions.locations?.excludeLocations.includes('AllTrusted')}
              onChange={() => setDraft({ ...draft, conditions: { ...draft.conditions, locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] } } })}
            />
            All locations except trusted
          </label>
        </fieldset>
      )}

      {section === 'Conditions' && (
        <>
          <h3>Client apps</h3>
          {CLIENT_TYPES.map((c) => (
            <label className="check" key={c.id}>
              <input
                type="checkbox"
                checked={draft.conditions.clientAppTypes.includes(c.id)}
                onChange={(e) => {
                  let clientAppTypes = e.target.checked
                    ? [...draft.conditions.clientAppTypes.filter((t) => t !== 'all' || c.id === 'all'), c.id]
                    : draft.conditions.clientAppTypes.filter((t) => t !== c.id);
                  if (c.id === 'all' && e.target.checked) clientAppTypes = ['all'];
                  if (!clientAppTypes.length) clientAppTypes = ['all'];
                  setDraft({ ...draft, conditions: { ...draft.conditions, clientAppTypes } });
                }}
              />
              {c.label}
            </label>
          ))}
          <h3>Risk</h3>
          {(['high', 'medium', 'low'] as const).map((level) => (
            <label className="check" key={`s-${level}`}>
              <input
                type="checkbox"
                checked={draft.conditions.signInRiskLevels.includes(level)}
                onChange={(e) => {
                  const signInRiskLevels = e.target.checked
                    ? [...draft.conditions.signInRiskLevels, level]
                    : draft.conditions.signInRiskLevels.filter((x) => x !== level);
                  setDraft({ ...draft, conditions: { ...draft.conditions, signInRiskLevels } });
                }}
              />
              Sign-in risk: {level}
            </label>
          ))}
          {(['high', 'medium', 'low'] as const).map((level) => (
            <label className="check" key={`u-${level}`}>
              <input
                type="checkbox"
                checked={draft.conditions.userRiskLevels.includes(level)}
                onChange={(e) => {
                  const userRiskLevels = e.target.checked
                    ? [...draft.conditions.userRiskLevels, level]
                    : draft.conditions.userRiskLevels.filter((x) => x !== level);
                  setDraft({ ...draft, conditions: { ...draft.conditions, userRiskLevels } });
                }}
              />
              User risk: {level}
            </label>
          ))}
          <h3>Authentication flows</h3>
          <label className="check">
            <input
              type="checkbox"
              checked={!!draft.conditions.authenticationFlows?.transferMethods.includes('deviceCodeFlow')}
              onChange={(e) => {
                const current = draft.conditions.authenticationFlows?.transferMethods ?? [];
                const transferMethods = e.target.checked ? [...current, 'deviceCodeFlow'] : current.filter((x) => x !== 'deviceCodeFlow');
                setDraft({
                  ...draft,
                  conditions: {
                    ...draft.conditions,
                    authenticationFlows: transferMethods.length ? { transferMethods } : null,
                  },
                });
              }}
            />
            Device code flow
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={!!draft.conditions.authenticationFlows?.transferMethods.includes('authenticationTransfer')}
              onChange={(e) => {
                const current = draft.conditions.authenticationFlows?.transferMethods ?? [];
                const transferMethods = e.target.checked
                  ? [...current, 'authenticationTransfer']
                  : current.filter((x) => x !== 'authenticationTransfer');
                setDraft({
                  ...draft,
                  conditions: {
                    ...draft.conditions,
                    authenticationFlows: transferMethods.length ? { transferMethods } : null,
                  },
                });
              }}
            />
            Authentication transfer
          </label>
          <label className="field">
            Device filter rule (optional)
            <input
              value={draft.conditions.devices?.deviceFilter?.rule ?? ''}
              onChange={(e) => {
                const rule = e.target.value;
                setDraft({
                  ...draft,
                  conditions: {
                    ...draft.conditions,
                    devices: rule ? { deviceFilter: { mode: 'include', rule } } : null,
                  },
                });
              }}
              placeholder='device.isCompliant -ne True'
            />
          </label>
        </>
      )}

      {section === 'Grant' && (
        <>
          <label className="field">
            Operator
            <select
              value={grant.operator}
              onChange={(e) => setGrant({ ...grant, operator: e.target.value as 'AND' | 'OR' })}
            >
              <option value="AND">Require all (AND)</option>
              <option value="OR">Require one of (OR)</option>
            </select>
          </label>
          {BUILTIN.map((c) => (
            <label className="check" key={c.id}>
              <input
                type="checkbox"
                checked={grant.builtInControls.includes(c.id)}
                onChange={(e) => {
                  let builtInControls = e.target.checked
                    ? [...grant.builtInControls, c.id]
                    : grant.builtInControls.filter((x) => x !== c.id);
                  if (c.id === 'block' && e.target.checked) builtInControls = ['block'];
                  if (c.id !== 'block' && e.target.checked) builtInControls = builtInControls.filter((x) => x !== 'block');
                  setGrant({ ...grant, builtInControls });
                }}
              />
              {c.label}
            </label>
          ))}
          <label className="field">
            Authentication strength
            <select
              value={grant.authenticationStrength?.id ?? ''}
              onChange={(e) => {
                const id = e.target.value;
                const map: Record<string, { id: string; displayName: string }> = {
                  [AUTH_STRENGTH.mfa]: { id: AUTH_STRENGTH.mfa, displayName: 'Multifactor authentication' },
                  [AUTH_STRENGTH.passwordless]: { id: AUTH_STRENGTH.passwordless, displayName: 'Passwordless MFA' },
                  [AUTH_STRENGTH.phishingResistant]: { id: AUTH_STRENGTH.phishingResistant, displayName: 'Phishing-resistant MFA' },
                };
                setGrant({ ...grant, authenticationStrength: id ? { ...map[id], requirementsSatisfied: 'mfa' } : null });
              }}
            >
              <option value="">None</option>
              <option value={AUTH_STRENGTH.mfa}>Multifactor authentication</option>
              <option value={AUTH_STRENGTH.passwordless}>Passwordless MFA</option>
              <option value={AUTH_STRENGTH.phishingResistant}>Phishing-resistant MFA</option>
            </select>
          </label>
        </>
      )}

      {section === 'Session' && (
        <>
          <label className="check">
            <input
              type="checkbox"
              checked={!!session?.signInFrequency?.isEnabled}
              onChange={(e) => setDraft({
                ...draft,
                sessionControls: {
                  ...(session ?? emptySession()),
                  signInFrequency: e.target.checked
                    ? { isEnabled: true, type: 'hours', value: session?.signInFrequency?.value ?? 4, frequencyInterval: 'timeBased' }
                    : null,
                },
              })}
            />
            Sign-in frequency
          </label>
          {session?.signInFrequency?.isEnabled && (
            <label className="field">
              Hours
              <input
                type="number"
                min={1}
                value={session.signInFrequency.value ?? 4}
                onChange={(e) => setDraft({
                  ...draft,
                  sessionControls: {
                    ...(session ?? emptySession()),
                    signInFrequency: { ...session.signInFrequency!, value: Number(e.target.value), type: 'hours', isEnabled: true },
                  },
                })}
              />
            </label>
          )}
          <label className="field">
            Persistent browser
            <select
              value={session?.persistentBrowser?.isEnabled ? session.persistentBrowser.mode : 'off'}
              onChange={(e) => {
                const v = e.target.value;
                setDraft({
                  ...draft,
                  sessionControls: {
                    ...(session ?? emptySession()),
                    persistentBrowser: v === 'off' ? null : { isEnabled: true, mode: v as 'always' | 'never' },
                  },
                });
              }}
            >
              <option value="off">Not configured</option>
              <option value="never">Never persist</option>
              <option value="always">Always persist</option>
            </select>
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={session?.disableResilienceDefaults === true}
              onChange={(e) => setDraft({
                ...draft,
                sessionControls: { ...(session ?? emptySession()), disableResilienceDefaults: e.target.checked ? true : null },
              })}
            />
            Disable resilience defaults
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={session?.continuousAccessEvaluation?.mode === 'disabled'}
              onChange={(e) => setDraft({
                ...draft,
                sessionControls: {
                  ...(session ?? emptySession()),
                  continuousAccessEvaluation: e.target.checked ? { mode: 'disabled' } : null,
                },
              })}
            />
            Disable continuous access evaluation
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={!!session?.secureSignInSession?.isEnabled}
              onChange={(e) => setDraft({
                ...draft,
                sessionControls: {
                  ...(session ?? emptySession()),
                  secureSignInSession: e.target.checked ? { isEnabled: true } : null,
                },
              })}
            />
            Token protection (secure sign-in session)
          </label>
        </>
      )}

      <div className="footer-nav">
        <button type="button" className="btn secondary" onClick={onCancel}>Cancel</button>
        <button type="button" className="btn" onClick={() => onSave(draft)}>Save policy</button>
      </div>
    </div>
  );
}

function emptySession() {
  return {
    applicationEnforcedRestrictions: null,
    cloudAppSecurity: null,
    signInFrequency: null,
    persistentBrowser: null,
    continuousAccessEvaluation: null,
    secureSignInSession: null,
    disableResilienceDefaults: null,
  };
}
