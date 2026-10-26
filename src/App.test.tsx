import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, test } from 'vitest';
import App from './App';
import { STORAGE_KEY } from './ui/state';

afterEach(() => {
  localStorage.removeItem(STORAGE_KEY);
});

test('starts on tenant setup and Next moves to Policies', () => {
  render(<App />);
  expect(screen.getByRole('heading', { name: 'CA Gap Evaluator' })).toBeTruthy();
  expect(screen.getByRole('heading', { name: 'Tenant setup' })).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Next' }));
  expect(screen.getByRole('heading', { name: 'Policies' })).toBeTruthy();
});

test('toggling Entra ID P2 updates the checkbox', () => {
  render(<App />);
  const box = screen.getByLabelText('Entra ID P2') as HTMLInputElement;
  expect(box.checked).toBe(false);
  fireEvent.click(box);
  expect(box.checked).toBe(true);
});

test('weak sample loads policies and analysis shows a gap', () => {
  render(<App />);
  fireEvent.click(screen.getByRole('button', { name: 'Next' }));
  fireEvent.click(screen.getByRole('button', { name: 'Load sample: weak' }));
  expect(screen.getByText(/CA01 - Require MFA/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: '3. Analysis' }));
  expect(screen.getByRole('heading', { name: 'Analysis' })).toBeTruthy();
  expect(screen.getAllByText('BAS-03').length).toBeGreaterThan(0);
  expect(document.querySelector('[data-state="gap"]')).toBeTruthy();
});
