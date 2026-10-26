import { expect, test } from 'vitest';
import { CATALOG_DATE } from '../catalog/apps';
import { analyze } from '../engine/analyze';
import { DEFAULT_TENANT } from '../model/types';
import { buildHtmlReport } from './html';

test('HTML report is self-contained', () => {
  const result = analyze([], DEFAULT_TENANT);
  const html = buildHtmlReport({ tenant: DEFAULT_TENANT, policies: [], result });
  expect(html.startsWith('<!DOCTYPE html>')).toBe(true);
  expect(html).not.toMatch(/https?:\/\/cdn\./);
  expect(html).toContain('CA Gap Evaluator report');
  expect(html).toContain(CATALOG_DATE);
  expect(html).toContain(`Score: ${result.score}`);
});
