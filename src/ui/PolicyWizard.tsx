import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { APP_CATALOG, KEYWORD, USER_ACTION, appLabel } from '../catalog/apps';
import { AUTH_STRENGTH } from '../catalog/authStrengths';
import { EXTENDED_ROLES, PRIVILEGED_ROLES, roleName } from '../catalog/roles';
import type { CAApplications, CAPolicy, CAUsers, PolicyState } from '../model/types';
import { locationDisplayName } from '../catalog/locations';
import { ALL_GUEST_TYPES, linesOf } from './labels';
import { LocationPicker } from './LocationPicker';

const PLATFORMS = [
  { id: 'android', label: 'Android' },
  { id: 'iOS', label: 'iOS' },
  { id: 'windows', label: 'Windows' },
  { id: 'macOS', label: 'macOS' },
  { id: 'linux', label: 'Linux' },
  { id: 'windowsPhone', label: 'Windows Phone' },
];

const GRANT_CONTROLS = [
  { id: 'mfa', label: 'Require multifactor authentication' },
  { id: 'compliantDevice', label: 'Require device to be marked as compliant' },
  { id: 'domainJoinedDevice', label: 'Require Microsoft Entra hybrid joined device' },
  { id: 'compliantApplication', label: 'Require app protection policy' },
  { id: 'approvedApplication', label: 'Require approved client app' },
  { id: 'passwordChange', label: 'Require password change' },
];

const RISK = ['high', 'medium', 'low'] as const;
const INSIDER = ['elevated', 'moderate', 'minor'] as const;

interface Props {
  policy: CAPolicy;
  onSave: (policy: CAPolicy) => void;
  onCancel: () => void;
  onDirtyChange?: (dirty: boolean) => void;
}

type TargetKind = 'apps' | 'userActions' | 'authContext';

export function PolicyWizard({ policy, onSave, onCancel, onDirtyChange }: Props) {
  const [draft, setDraft] = useState<CAPolicy>(() => structuredClone(policy));
  useEffect(() => {
    onDirtyChange?.(JSON.stringify(draft) !== JSON.stringify(policy));
  }, [draft, policy, onDirtyChange]);
  const [appQuery, setAppQuery] = useState('');
  const [customApp, setCustomApp] = useState('');
  const [showAllRoles, setShowAllRoles] = useState(false);
  const [includeMode, setIncludeMode] = useState<TargetKind>(() =>
    policy.conditions.applications.includeUserActions.length
      ? 'userActions'
      : policy.conditions.applications.includeAuthenticationContextClassReferences.length
        ? 'authContext'
        : 'apps',
  );

  const users = draft.conditions.users;
  const apps = draft.conditions.applications;
  const grant = draft.grantControls ?? emptyGrant();
  const session = draft.sessionControls;
  const blocking = grant.builtInControls.includes('block');

  const filteredApps = useMemo(() => {
    const q = appQuery.trim().toLowerCase();
    return APP_CATALOG.filter((a) =>
      !q || a.name.toLowerCase().includes(q) || a.appId.includes(q) || a.aliases.some((x) => x.toLowerCase().includes(q)),
    );
  }, [appQuery]);

  function patch(next: Partial<CAPolicy>) {
    setDraft({ ...draft, ...next });
  }
  function setUsers(next: Partial<CAUsers>) {
    patch({ conditions: { ...draft.conditions, users: { ...users, ...next } } });
  }
  function setApps(next: Partial<CAApplications>) {
    patch({ conditions: { ...draft.conditions, applications: { ...apps, ...next } } });
  }
  function setGrant(next: typeof grant) {
    patch({ grantControls: next });
  }
  function setLocations(next: NonNullable<CAPolicy['conditions']['locations']> | null) {
    patch({ conditions: { ...draft.conditions, locations: next } });
  }
  function currentLocations() {
    return draft.conditions.locations ?? { includeLocations: ['All'] as string[], excludeLocations: [] as string[] };
  }

  const roles = showAllRoles ? [...PRIVILEGED_ROLES, ...EXTENDED_ROLES] : PRIVILEGED_ROLES;

  return (
    <form
      className="wizard"
      onSubmit={(e) => {
        e.preventDefault();
        onSave(draft);
      }}
    >
      <p className="kicker">Microsoft Entra</p>
      <h2>{draft.id === policy.id && policy.displayName !== 'New policy' ? 'Edit' : 'New'} Conditional Access policy</h2>
      <p className="lede">The same assignment, condition, and access-control sections as the Entra admin center.</p>

      <label className="field">
        Name
        <input value={draft.displayName} onChange={(e) => patch({ displayName: e.target.value })} />
      </label>

      <h3 className="group-title">Assignments</h3>
      <div className="blade-stack">
      <Blade title="Users" summary={userSummary(users)}>
        <p className="subhead">Include</p>
        <Radio name="incUsers" checked={users.includeUsers.includes('None') && users.includeUsers.length === 1} onChange={() => setUsers({ includeUsers: ['None'], includeGroups: [], includeRoles: [], includeGuestsOrExternalUsers: null })} label="None" />
        <Radio name="incUsers" checked={users.includeUsers.includes('All')} onChange={() => setUsers({ includeUsers: ['All'] })} label="All users" />
        <Radio
          name="incUsers"
          checked={!users.includeUsers.includes('All') && !(users.includeUsers.length === 1 && users.includeUsers[0] === 'None')}
          onChange={() => setUsers({ includeUsers: users.includeUsers.filter((u) => u !== 'All' && u !== 'None') })}
          label="Select users and groups"
        />
        {!users.includeUsers.includes('All') && !(users.includeUsers.length === 1 && users.includeUsers[0] === 'None') && (
          <>
            <label className="field">
              Users
              <textarea rows={3} placeholder="One object ID per line" value={users.includeUsers.join('\n')} onChange={(e) => setUsers({ includeUsers: linesOf(e.target.value) })} />
            </label>
            <label className="field">
              Groups
              <textarea rows={2} value={users.includeGroups.join('\n')} onChange={(e) => setUsers({ includeGroups: linesOf(e.target.value) })} />
            </label>
          </>
        )}
        <label className="check">
          <input
            type="checkbox"
            checked={!!users.includeGuestsOrExternalUsers}
            onChange={(e) => setUsers({
              includeGuestsOrExternalUsers: e.target.checked
                ? { guestOrExternalUserTypes: [...ALL_GUEST_TYPES], externalTenants: { membershipKind: 'all' } }
                : null,
            })}
          />
          Guest or external users
        </label>
        {users.includeGuestsOrExternalUsers && (
          <div className="indent">
            {ALL_GUEST_TYPES.map((t) => (
              <label className="check" key={t}>
                <input
                  type="checkbox"
                  checked={users.includeGuestsOrExternalUsers!.guestOrExternalUserTypes.includes(t)}
                  onChange={(e) => {
                    const current = users.includeGuestsOrExternalUsers!.guestOrExternalUserTypes;
                    const guestOrExternalUserTypes = e.target.checked ? [...current, t] : current.filter((x) => x !== t);
                    setUsers({ includeGuestsOrExternalUsers: { ...users.includeGuestsOrExternalUsers!, guestOrExternalUserTypes } });
                  }}
                />
                {guestLabel(t)}
              </label>
            ))}
          </div>
        )}
        <p className="subhead">Directory roles</p>
        {roles.map((r) => (
          <label className="check" key={r.id}>
            <input
              type="checkbox"
              checked={users.includeRoles.includes(r.id)}
              onChange={(e) => setUsers({
                includeRoles: e.target.checked ? [...users.includeRoles, r.id] : users.includeRoles.filter((id) => id !== r.id),
              })}
            />
            {r.name}
          </label>
        ))}
        <button type="button" className="btn secondary" onClick={() => setShowAllRoles((v) => !v)}>
          {showAllRoles ? 'Show fewer roles' : 'Show more roles'}
        </button>

        <p className="subhead">Exclude</p>
        <label className="field">
          Users
          <textarea rows={2} placeholder="Break-glass object IDs or UPNs" value={users.excludeUsers.join('\n')} onChange={(e) => setUsers({ excludeUsers: linesOf(e.target.value) })} />
        </label>
        <label className="field">
          Groups
          <textarea rows={2} value={users.excludeGroups.join('\n')} onChange={(e) => setUsers({ excludeGroups: linesOf(e.target.value) })} />
        </label>
        <label className="field">
          Directory roles
          <textarea rows={2} placeholder="Role template IDs" value={users.excludeRoles.join('\n')} onChange={(e) => setUsers({ excludeRoles: linesOf(e.target.value) })} />
        </label>
        {users.excludeRoles.length > 0 && (
          <p className="muted">{users.excludeRoles.map((id) => roleName(id) ?? id).join(', ')}</p>
        )}
      </Blade>

      <Blade title="Target resources" summary={resourceSummary(apps)}>
        <p className="subhead">Include</p>
        <Radio name="targetKind" checked={includeMode === 'apps'} onChange={() => { setIncludeMode('apps'); setApps({ includeUserActions: [], includeAuthenticationContextClassReferences: [] }); }} label="Cloud apps" />
        <Radio name="targetKind" checked={includeMode === 'userActions'} onChange={() => { setIncludeMode('userActions'); setApps({ includeApplications: [], includeAuthenticationContextClassReferences: [] }); }} label="User actions" />
        <Radio name="targetKind" checked={includeMode === 'authContext'} onChange={() => { setIncludeMode('authContext'); setApps({ includeApplications: [], includeUserActions: [] }); }} label="Authentication context" />

        {includeMode === 'apps' && (
          <>
            <Radio name="apps" checked={apps.includeApplications.length === 1 && apps.includeApplications[0] === KEYWORD.none} onChange={() => setApps({ includeApplications: [KEYWORD.none] })} label="None" />
            <Radio name="apps" checked={apps.includeApplications.includes(KEYWORD.all)} onChange={() => setApps({ includeApplications: [KEYWORD.all] })} label="All resources" />
            <Radio
              name="apps"
              checked={!apps.includeApplications.includes(KEYWORD.all) && !(apps.includeApplications.length === 1 && apps.includeApplications[0] === KEYWORD.none)}
              onChange={() => setApps({ includeApplications: apps.includeApplications.filter((id) => id !== KEYWORD.all && id !== KEYWORD.none) })}
              label="Select resources"
            />
            {!apps.includeApplications.includes(KEYWORD.all) && !(apps.includeApplications.length === 1 && apps.includeApplications[0] === KEYWORD.none) && (
              <>
                <label className="check">
                  <input type="checkbox" checked={apps.includeApplications.includes(KEYWORD.office365)} onChange={(e) => toggleApp(apps, KEYWORD.office365, e.target.checked, setApps)} />
                  Office 365
                </label>
                <label className="check">
                  <input type="checkbox" checked={apps.includeApplications.includes(KEYWORD.adminPortals)} onChange={(e) => toggleApp(apps, KEYWORD.adminPortals, e.target.checked, setApps)} />
                  Microsoft Admin Portals
                </label>
                {apps.includeApplications.includes(KEYWORD.adminPortals) && (
                  <p className="warn">Microsoft Admin Portals covers portal sign-in only. It does not cover Microsoft Graph, the Intune API, or Azure Resource Manager.</p>
                )}
                <input className="search" value={appQuery} onChange={(e) => setAppQuery(e.target.value)} placeholder="Search resources" aria-label="Search resources" />
                <div className="app-pick">
                  {filteredApps.map((a) => (
                    <label className="check" key={a.appId}>
                      <input type="checkbox" checked={apps.includeApplications.includes(a.appId)} onChange={(e) => toggleApp(apps, a.appId, e.target.checked, setApps)} />
                      <span>
                        {a.name}
                        {!a.targetable && <span className="app-note"> This is a client app and cannot be targeted. Microsoft Graph can only be covered via All resources.</span>}
                        <span className="app-note">{a.appId}</span>
                      </span>
                    </label>
                  ))}
                </div>
                <label className="field">
                  Resource ID
                  <input value={customApp} onChange={(e) => setCustomApp(e.target.value)} />
                </label>
                <button type="button" className="btn secondary" onClick={() => {
                  const id = customApp.trim();
                  if (!id || apps.includeApplications.includes(id)) return;
                  setApps({ includeApplications: [...apps.includeApplications, id] });
                  setCustomApp('');
                }}>Add</button>
              </>
            )}
          </>
        )}

        {includeMode === 'userActions' && (
          <>
            <label className="check">
              <input
                type="checkbox"
                checked={apps.includeUserActions.includes(USER_ACTION.registerSecurityInfo)}
                onChange={(e) => setApps({ includeUserActions: toggleList(apps.includeUserActions, USER_ACTION.registerSecurityInfo, e.target.checked) })}
              />
              User action: Register security information
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={apps.includeUserActions.includes(USER_ACTION.registerDevice)}
                onChange={(e) => setApps({ includeUserActions: toggleList(apps.includeUserActions, USER_ACTION.registerDevice, e.target.checked) })}
              />
              Register or join devices
            </label>
            <p className="muted">Register or join devices only supports MFA or an authentication strength.</p>
          </>
        )}

        {includeMode === 'authContext' && (
          <label className="field">
            Authentication context
            <input
              value={apps.includeAuthenticationContextClassReferences.join(', ')}
              onChange={(e) => setApps({ includeAuthenticationContextClassReferences: e.target.value.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean) })}
              placeholder="c1, c2"
            />
          </label>
        )}

        <p className="subhead">Exclude</p>
        <label className="field">
          Excluded cloud apps
          <textarea rows={3} placeholder="App IDs, Office365, or MicrosoftAdminPortals" value={apps.excludeApplications.join('\n')} onChange={(e) => setApps({ excludeApplications: linesOf(e.target.value) })} />
        </label>
        {apps.excludeApplications.length > 0 && (
          <p className="muted">{apps.excludeApplications.map(appLabel).join(', ')}</p>
        )}
      </Blade>

      <Blade title="Network" summary={networkSummary(draft)}>
        <p className="subhead">Configure</p>
        <Radio name="netConfig" checked={!draft.conditions.locations} onChange={() => setLocations(null)} label="No" />
        <Radio name="netConfig" checked={!!draft.conditions.locations} onChange={() => setLocations(currentLocations())} label="Yes" />
        {draft.conditions.locations && (
          <div className="inc-exc">
            <div>
              <p className="subhead">Include</p>
              <Radio
                name="netInclude"
                checked={draft.conditions.locations.includeLocations.includes('All')}
                onChange={() => setLocations({ includeLocations: ['All'], excludeLocations: draft.conditions.locations!.excludeLocations })}
                label="Any location"
              />
              <Radio
                name="netInclude"
                checked={draft.conditions.locations.includeLocations.includes('AllTrusted')}
                onChange={() => setLocations({ includeLocations: ['AllTrusted'], excludeLocations: draft.conditions.locations!.excludeLocations })}
                label="All trusted locations"
              />
              <Radio
                name="netInclude"
                checked={!draft.conditions.locations.includeLocations.includes('All') && !draft.conditions.locations.includeLocations.includes('AllTrusted')}
                onChange={() => setLocations({
                  includeLocations: customLocations(draft.conditions.locations!.includeLocations),
                  excludeLocations: draft.conditions.locations!.excludeLocations,
                })}
                label="Selected locations"
              />
              {!draft.conditions.locations.includeLocations.includes('All') && !draft.conditions.locations.includeLocations.includes('AllTrusted') && (
                <LocationPicker
                  kind="Include"
                  selected={customLocations(draft.conditions.locations.includeLocations)}
                  onChange={(includeLocations) => setLocations({ includeLocations, excludeLocations: draft.conditions.locations!.excludeLocations })}
                />
              )}
            </div>
            <div>
              <p className="subhead">Exclude</p>
              <p className="muted">Selected locations</p>
              <label className="check">
                <input
                  type="checkbox"
                  checked={draft.conditions.locations.excludeLocations.includes('AllTrusted')}
                  onChange={(e) => {
                    const loc = draft.conditions.locations!;
                    setLocations({
                      includeLocations: loc.includeLocations,
                      excludeLocations: e.target.checked
                        ? [...loc.excludeLocations.filter((id) => id !== 'AllTrusted'), 'AllTrusted']
                        : loc.excludeLocations.filter((id) => id !== 'AllTrusted'),
                    });
                  }}
                />
                All trusted locations
              </label>
              <LocationPicker
                kind="Exclude"
                selected={customLocations(draft.conditions.locations.excludeLocations)}
                onChange={(ids) => {
                  const loc = draft.conditions.locations!;
                  const trusted = loc.excludeLocations.includes('AllTrusted') ? ['AllTrusted'] : [];
                  setLocations({ includeLocations: loc.includeLocations, excludeLocations: [...trusted, ...ids] });
                }}
              />
            </div>
          </div>
        )}
      </Blade>

      <Blade title="Conditions" summary={conditionsSummary(draft)}>
      <div className="blade-stack nested">
      <Blade title="User risk" summary={levelSummary(draft.conditions.userRiskLevels)}>
        {RISK.map((level) => (
          <label className="check" key={level}>
            <input type="checkbox" checked={draft.conditions.userRiskLevels.includes(level)} onChange={(e) => patch({ conditions: { ...draft.conditions, userRiskLevels: toggleList(draft.conditions.userRiskLevels, level, e.target.checked) } })} />
            {level}
          </label>
        ))}
      </Blade>
      <Blade title="Sign-in risk" summary={levelSummary(draft.conditions.signInRiskLevels)}>
        {RISK.map((level) => (
          <label className="check" key={level}>
            <input type="checkbox" checked={draft.conditions.signInRiskLevels.includes(level)} onChange={(e) => patch({ conditions: { ...draft.conditions, signInRiskLevels: toggleList(draft.conditions.signInRiskLevels, level, e.target.checked) } })} />
            {level}
          </label>
        ))}
      </Blade>
      <Blade title="Insider risk" summary={levelSummary(draft.conditions.insiderRiskLevels)}>
        {INSIDER.map((level) => (
          <label className="check" key={level}>
            <input type="checkbox" checked={draft.conditions.insiderRiskLevels.includes(level)} onChange={(e) => patch({ conditions: { ...draft.conditions, insiderRiskLevels: toggleList(draft.conditions.insiderRiskLevels, level, e.target.checked) } })} />
            {level}
          </label>
        ))}
      </Blade>
      <Blade title="Device platforms" summary={draft.conditions.platforms ? 'Configured' : 'Not configured'}>
        <Radio name="plat" checked={!draft.conditions.platforms} onChange={() => patch({ conditions: { ...draft.conditions, platforms: null } })} label="Not configured" />
        <Radio name="plat" checked={!!draft.conditions.platforms} onChange={() => patch({ conditions: { ...draft.conditions, platforms: draft.conditions.platforms ?? { includePlatforms: ['all'], excludePlatforms: [] } } })} label="Configure" />
        {draft.conditions.platforms && (
          <>
            <p className="subhead">Include</p>
            <label className="check">
              <input type="checkbox" checked={draft.conditions.platforms.includePlatforms.includes('all')} onChange={(e) => patch({ conditions: { ...draft.conditions, platforms: { ...draft.conditions.platforms!, includePlatforms: e.target.checked ? ['all'] : [] } } })} />
              Any device
            </label>
            <p className="subhead">Exclude</p>
            {PLATFORMS.map((p) => (
              <label className="check" key={p.id}>
                <input
                  type="checkbox"
                  checked={draft.conditions.platforms!.excludePlatforms.includes(p.id)}
                  onChange={(e) => patch({ conditions: { ...draft.conditions, platforms: { ...draft.conditions.platforms!, excludePlatforms: toggleList(draft.conditions.platforms!.excludePlatforms, p.id, e.target.checked) } } })}
                />
                {p.label}
              </label>
            ))}
          </>
        )}
      </Blade>
      <Blade title="Client apps" summary={draft.conditions.clientAppTypes.includes('all') ? 'All clients' : draft.conditions.clientAppTypes.join(', ')}>
        <p className="muted">Modern authentication clients</p>
        <ClientCheck draft={draft} id="browser" label="Browser" onChange={(clientAppTypes) => patch({ conditions: { ...draft.conditions, clientAppTypes } })} />
        <ClientCheck draft={draft} id="mobileAppsAndDesktopClients" label="Mobile apps and desktop clients" onChange={(clientAppTypes) => patch({ conditions: { ...draft.conditions, clientAppTypes } })} />
        <p className="muted">Legacy authentication clients</p>
        <ClientCheck draft={draft} id="exchangeActiveSync" label="Exchange ActiveSync" onChange={(clientAppTypes) => patch({ conditions: { ...draft.conditions, clientAppTypes } })} />
        <ClientCheck draft={draft} id="other" label="Other clients" onChange={(clientAppTypes) => patch({ conditions: { ...draft.conditions, clientAppTypes } })} />
        <label className="check">
          <input type="checkbox" checked={draft.conditions.clientAppTypes.includes('all')} onChange={() => patch({ conditions: { ...draft.conditions, clientAppTypes: ['all'] } })} />
          All clients
        </label>
      </Blade>
      <Blade title="Filter for devices" summary={draft.conditions.devices?.deviceFilter?.rule ? 'Configured' : 'Not configured'}>
        <label className="field">
          Mode
          <select
            value={draft.conditions.devices?.deviceFilter?.mode ?? 'include'}
            onChange={(e) => patch({ conditions: { ...draft.conditions, devices: { deviceFilter: { mode: e.target.value as 'include' | 'exclude', rule: draft.conditions.devices?.deviceFilter?.rule ?? '' } } } })}
          >
            <option value="include">Include filtered devices in policy</option>
            <option value="exclude">Exclude filtered devices from policy</option>
          </select>
        </label>
        <label className="field">
          Rule syntax
          <input
            value={draft.conditions.devices?.deviceFilter?.rule ?? ''}
            placeholder='device.isCompliant -ne True'
            onChange={(e) => {
              const rule = e.target.value;
              patch({ conditions: { ...draft.conditions, devices: rule ? { deviceFilter: { mode: draft.conditions.devices?.deviceFilter?.mode ?? 'include', rule } } : null } });
            }}
          />
        </label>
      </Blade>
      <Blade title="Authentication flows" summary={draft.conditions.authenticationFlows?.transferMethods.join(', ') || 'Not configured'}>
        <label className="check">
          <input type="checkbox" checked={!!draft.conditions.authenticationFlows?.transferMethods.includes('deviceCodeFlow')} onChange={(e) => setFlows(draft, 'deviceCodeFlow', e.target.checked, patch)} />
          Device code flow
        </label>
        <label className="check">
          <input type="checkbox" checked={!!draft.conditions.authenticationFlows?.transferMethods.includes('authenticationTransfer')} onChange={(e) => setFlows(draft, 'authenticationTransfer', e.target.checked, patch)} />
          Authentication transfer
        </label>
      </Blade>
      </div>
      </Blade>
      </div>

      <h3 className="group-title">Access controls</h3>
      <div className="blade-stack">
      <Blade title="Grant" summary={blocking ? 'Block access' : grantSummary(grant)}>
        <Radio name="grantMode" checked={blocking} onChange={() => setGrant({ ...grant, builtInControls: ['block'], authenticationStrength: null })} label="Block access" />
        <Radio name="grantMode" checked={!blocking} onChange={() => setGrant({ ...grant, builtInControls: grant.builtInControls.filter((c) => c !== 'block') })} label="Grant access" />
        {!blocking && (
          <>
            {GRANT_CONTROLS.map((c) => (
              <label className="check" key={c.id}>
                <input
                  type="checkbox"
                  checked={grant.builtInControls.includes(c.id)}
                  onChange={(e) => setGrant({ ...grant, builtInControls: toggleList(grant.builtInControls.filter((x) => x !== 'block'), c.id, e.target.checked) })}
                />
                {c.label}
              </label>
            ))}
            <label className="field">
              Authentication strength
              <select
                aria-label="Authentication strength"
                value={grant.authenticationStrength?.id ?? ''}
                onChange={(e) => {
                  const id = e.target.value;
                  const names: Record<string, string> = {
                    [AUTH_STRENGTH.mfa]: 'Multifactor authentication',
                    [AUTH_STRENGTH.passwordless]: 'Passwordless MFA',
                    [AUTH_STRENGTH.phishingResistant]: 'Phishing-resistant MFA',
                  };
                  setGrant({ ...grant, authenticationStrength: id ? { id, displayName: names[id], requirementsSatisfied: 'mfa' } : null });
                }}
              >
                <option value="">Not required</option>
                <option value={AUTH_STRENGTH.mfa}>Multifactor authentication</option>
                <option value={AUTH_STRENGTH.passwordless}>Passwordless MFA</option>
                <option value={AUTH_STRENGTH.phishingResistant}>Phishing-resistant MFA</option>
              </select>
            </label>
            <p className="subhead">For multiple controls</p>
            <Radio name="op" checked={grant.operator === 'AND'} onChange={() => setGrant({ ...grant, operator: 'AND' })} label="Require all the selected controls" />
            <Radio name="op" checked={grant.operator === 'OR'} onChange={() => setGrant({ ...grant, operator: 'OR' })} label="Require one of the selected controls" />
          </>
        )}
      </Blade>

      <Blade title="Session" summary={sessionSummary(session)}>
        <label className="check">
          <input
            type="checkbox"
            checked={!!session?.signInFrequency?.isEnabled}
            onChange={(e) => patch({
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
            <input type="number" min={1} value={session.signInFrequency.value ?? 4} onChange={(e) => patch({
              sessionControls: { ...(session ?? emptySession()), signInFrequency: { ...session.signInFrequency!, value: Number(e.target.value), type: 'hours', isEnabled: true } },
            })} />
          </label>
        )}
        <label className="field">
          Persistent browser session
          <select
            value={session?.persistentBrowser?.isEnabled ? session.persistentBrowser.mode : 'off'}
            onChange={(e) => {
              const v = e.target.value;
              patch({ sessionControls: { ...(session ?? emptySession()), persistentBrowser: v === 'off' ? null : { isEnabled: true, mode: v as 'always' | 'never' } } });
            }}
          >
            <option value="off">Not configured</option>
            <option value="never">Never persistent</option>
            <option value="always">Always persistent</option>
          </select>
        </label>
        <label className="check">
          <input type="checkbox" checked={session?.disableResilienceDefaults === true} onChange={(e) => patch({ sessionControls: { ...(session ?? emptySession()), disableResilienceDefaults: e.target.checked ? true : null } })} />
          Disable resilience defaults
        </label>
        <label className="check">
          <input type="checkbox" checked={session?.continuousAccessEvaluation?.mode === 'disabled'} onChange={(e) => patch({ sessionControls: { ...(session ?? emptySession()), continuousAccessEvaluation: e.target.checked ? { mode: 'disabled' } : null } })} />
          Customize continuous access evaluation
        </label>
        <label className="check">
          <input type="checkbox" checked={!!session?.secureSignInSession?.isEnabled} onChange={(e) => patch({ sessionControls: { ...(session ?? emptySession()), secureSignInSession: e.target.checked ? { isEnabled: true } : null } })} />
          Token protection
        </label>
      </Blade>
      </div>

      <h3 className="group-title">Enable policy</h3>
      <div className="enable-policy">
        <Radio name="state" checked={draft.state === 'enabledForReportingButNotEnforced'} onChange={() => patch({ state: 'enabledForReportingButNotEnforced' satisfies PolicyState })} label="Report-only" />
        <Radio name="state" checked={draft.state === 'enabled'} onChange={() => patch({ state: 'enabled' })} label="On" />
        <Radio name="state" checked={draft.state === 'disabled'} onChange={() => patch({ state: 'disabled' })} label="Off" />
      </div>

      <div className="footer-nav">
        <button type="button" className="btn secondary" onClick={onCancel}>Cancel</button>
        <button type="submit" className="btn">Save policy</button>
      </div>
    </form>
  );
}

function Blade({ title, summary, children }: { title: string; summary: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`blade${open ? ' open' : ''}`}>
      <button type="button" className="blade-row" aria-expanded={open} aria-label={title} onClick={() => setOpen((v) => !v)}>
        <span className="chevron" aria-hidden="true" />
        <span className="blade-title">{title}</span>
        <span className="blade-summary" aria-hidden="true">{open ? '' : summary}</span>
      </button>
      {open && <div className="blade-body">{children}</div>}
    </div>
  );
}

function Radio({ name, checked, onChange, label }: { name: string; checked: boolean; onChange: () => void; label: string }) {
  return (
    <label className="check">
      <input type="radio" name={name} checked={checked} onChange={onChange} />
      {label}
    </label>
  );
}

function ClientCheck({ draft, id, label, onChange }: { draft: CAPolicy; id: string; label: string; onChange: (types: string[]) => void }) {
  const types = draft.conditions.clientAppTypes;
  return (
    <label className="check">
      <input
        type="checkbox"
        checked={types.includes(id)}
        onChange={(e) => {
          let next = e.target.checked ? [...types.filter((t) => t !== 'all'), id] : types.filter((t) => t !== id);
          if (!next.length) next = ['all'];
          onChange(next);
        }}
      />
      {label}
    </label>
  );
}

function toggleList(list: string[], id: string, on: boolean) {
  return on ? [...list, id] : list.filter((x) => x !== id);
}

function toggleApp(apps: CAApplications, id: string, on: boolean, setApps: (next: Partial<CAApplications>) => void) {
  const includeApplications = apps.includeApplications.filter((x) => x !== KEYWORD.all && x !== KEYWORD.none);
  setApps({ includeApplications: on ? [...includeApplications, id] : includeApplications.filter((x) => x !== id) });
}

function userSummary(users: CAUsers) {
  if (users.includeUsers.includes('All')) return 'All users';
  if (users.includeUsers.length === 1 && users.includeUsers[0] === 'None' && !users.includeGroups.length && !users.includeRoles.length && !users.includeGuestsOrExternalUsers) return 'None';
  const parts: string[] = [];
  if (users.includeUsers.some((u) => u !== 'All' && u !== 'None') || users.includeGroups.length) parts.push('Select users and groups');
  if (users.includeRoles.length) parts.push(`${users.includeRoles.length} roles`);
  if (users.includeGuestsOrExternalUsers) parts.push('Guests');
  return parts.join(', ') || 'Not configured';
}

function resourceSummary(apps: CAApplications) {
  if (apps.includeUserActions.length) return 'User actions';
  if (apps.includeAuthenticationContextClassReferences.length && !apps.includeApplications.length) return 'Authentication context';
  if (apps.includeApplications.includes(KEYWORD.all)) return 'All resources';
  if (apps.includeApplications.length === 1 && apps.includeApplications[0] === KEYWORD.office365) return 'Office 365';
  if (apps.includeApplications.length === 1 && apps.includeApplications[0] === KEYWORD.adminPortals) return 'Microsoft Admin Portals';
  if (apps.includeApplications.length) return apps.includeApplications.map(appLabel).slice(0, 2).join(', ');
  return 'Not configured';
}

function customLocations(ids: string[]) {
  return ids.filter((id) => id !== 'All' && id !== 'AllTrusted');
}

function networkSummary(draft: CAPolicy) {
  const loc = draft.conditions.locations;
  if (!loc) return '0 networks selected';
  const include = loc.includeLocations.includes('AllTrusted')
    ? 'All trusted locations'
    : loc.includeLocations.includes('All')
      ? 'Any location'
      : loc.includeLocations.map(locationDisplayName).slice(0, 2).join(', ') || 'Selected locations';
  const excluded = customLocations(loc.excludeLocations).map(locationDisplayName);
  const trusted = loc.excludeLocations.includes('AllTrusted') ? ['All trusted locations'] : [];
  const excl = [...trusted, ...excluded];
  return excl.length ? `${include}, exclude ${excl.slice(0, 2).join(', ')}` : include;
}

function conditionsSummary(draft: CAPolicy) {
  const configured = [
    draft.conditions.userRiskLevels.length,
    draft.conditions.signInRiskLevels.length,
    draft.conditions.insiderRiskLevels.length,
    draft.conditions.platforms,
    !draft.conditions.clientAppTypes.includes('all'),
    draft.conditions.devices?.deviceFilter?.rule,
    draft.conditions.authenticationFlows,
  ].filter(Boolean).length;
  return configured ? `${configured} configured` : '0 conditions selected';
}

function levelSummary(levels: string[]) {
  return levels.length ? levels.join(', ') : 'Not configured';
}

function grantSummary(grant: NonNullable<CAPolicy['grantControls']>) {
  const names = grant.builtInControls.filter((c) => c !== 'block');
  if (grant.authenticationStrength?.displayName) names.push(grant.authenticationStrength.displayName);
  if (!names.length) return 'Not configured';
  return `${grant.operator === 'AND' ? 'Require all' : 'Require one'}: ${names.join(', ')}`;
}

function sessionSummary(session: CAPolicy['sessionControls']) {
  if (!session) return 'Not configured';
  const parts: string[] = [];
  if (session.signInFrequency?.isEnabled) parts.push('Sign-in frequency');
  if (session.persistentBrowser?.isEnabled) parts.push('Persistent browser');
  if (session.secureSignInSession?.isEnabled) parts.push('Token protection');
  return parts.join(', ') || 'Not configured';
}

function setFlows(draft: CAPolicy, method: string, on: boolean, patch: (next: Partial<CAPolicy>) => void) {
  const current = draft.conditions.authenticationFlows?.transferMethods ?? [];
  const transferMethods = on ? [...current, method] : current.filter((x) => x !== method);
  patch({ conditions: { ...draft.conditions, authenticationFlows: transferMethods.length ? { transferMethods } : null } });
}

function guestLabel(id: string) {
  const labels: Record<string, string> = {
    internalGuest: 'Local guest users',
    b2bCollaborationGuest: 'B2B collaboration guest users',
    b2bCollaborationMember: 'B2B collaboration member users',
    b2bDirectConnectUser: 'B2B direct connect users',
    otherExternalUser: 'Other external users',
    serviceProvider: 'Service provider users',
  };
  return labels[id] ?? id;
}

function emptyGrant() {
  return { operator: 'OR' as const, builtInControls: [] as string[], customAuthenticationFactors: [] as string[], termsOfUse: [] as string[], authenticationStrength: null };
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
