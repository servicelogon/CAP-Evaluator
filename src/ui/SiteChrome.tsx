import { useEffect, useRef, useState } from 'react';

// The same chrome as newfrontiersecurity.net: logo, three links, a full-screen
// menu on phones, and the wireframe mark above the footer.
export const SITE = 'https://newfrontiersecurity.net';
const NAV_LINKS: [string, string][] = [
  ['Blog', `${SITE}/`],
  ['Newsroom', `${SITE}/newsroom`],
  ['Toolbox', `${SITE}/tools`],
];

function NavLinks() {
  return (
    <>
      {NAV_LINKS.map(([name, href]) => (
        <a key={name} href={href} aria-current={name === 'Toolbox' ? 'page' : undefined}>{name}</a>
      ))}
    </>
  );
}

export function SiteHeader() {
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    document.documentElement.classList.toggle('nav-open', menuOpen);
    if (!menuOpen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setMenuOpen(false); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [menuOpen]);

  return (
    <header className="topbar shell">
      <a className="brand" href={`${SITE}/`} aria-label="New Frontier Security home">
        <img
          className="brand-logo"
          src={`${import.meta.env.BASE_URL}new-frontier-security-logo.png`}
          width={837}
          height={349}
          alt="New Frontier Security"
        />
      </a>
      <div className="header-actions">
        <nav className="desktop-nav" aria-label="Main navigation"><NavLinks /></nav>
        <div className={`site-menu${menuOpen ? ' open' : ''}`}>
          <button
            type="button"
            className="menu-toggle"
            aria-expanded={menuOpen}
            aria-controls="mobile-nav"
            aria-label={menuOpen ? 'Close navigation menu' : 'Open navigation menu'}
            onClick={() => setMenuOpen((v) => !v)}
          >
            <span className="hamburger" aria-hidden="true" />
          </button>
          {menuOpen && (
            <nav id="mobile-nav" aria-label="Mobile navigation"><NavLinks /></nav>
          )}
        </div>
      </div>
    </header>
  );
}

export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="footer-mark"><FooterWire /></div>
      <div className="footer-base">
        <div className="footer-base-inner">
          <p className="footer-name">New Frontier Security</p>
          <nav className="footer-nav" aria-label="Footer"><NavLinks /></nav>
        </div>
      </div>
    </footer>
  );
}

// A hairline icosahedron that turns slowly, ported from the NFS site. A still
// frame when motion is reduced, and nothing at all where canvas is missing.
function FooterWire() {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas || /jsdom/i.test(navigator.userAgent)) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const phi = (1 + Math.sqrt(5)) / 2;
    const verts = [[-1, phi, 0], [1, phi, 0], [-1, -phi, 0], [1, -phi, 0], [0, -1, phi], [0, 1, phi], [0, -1, -phi], [0, 1, -phi], [phi, 0, -1], [phi, 0, 1], [-phi, 0, -1], [-phi, 0, 1]]
      .map(([x, y, z]) => { const l = Math.hypot(x, y, z); return [x / l, y / l, z / l]; });
    const edges = [[0, 1], [0, 5], [0, 7], [0, 10], [0, 11], [1, 5], [1, 7], [1, 8], [1, 9], [2, 3], [2, 4], [2, 6], [2, 10], [2, 11], [3, 4], [3, 6], [3, 8], [3, 9], [4, 5], [4, 9], [4, 11], [5, 9], [5, 11], [6, 7], [6, 8], [6, 10], [7, 8], [7, 10], [8, 9], [10, 11]];
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)');
    const tilt = 0.62;
    let frame = 0;
    let running = false;

    const size = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const w = canvas.clientWidth || 168;
      canvas.width = Math.max(1, Math.round(w * dpr));
      canvas.height = canvas.width;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    const project = ([x, y, z]: number[], yaw: number) => {
      const x1 = x * Math.cos(yaw) + z * Math.sin(yaw);
      const z1 = -x * Math.sin(yaw) + z * Math.cos(yaw);
      return { x: x1, y: y * Math.cos(tilt) - z1 * Math.sin(tilt), z: y * Math.sin(tilt) + z1 * Math.cos(tilt) };
    };
    const draw = (yaw: number) => {
      const w = canvas.clientWidth || 168;
      const r = w * 0.36;
      ctx.clearRect(0, 0, w, w);
      ctx.lineWidth = 1;
      ctx.strokeStyle = getComputedStyle(canvas).color;
      const lines = edges
        .map(([a, b]) => { const s = project(verts[a], yaw); const e = project(verts[b], yaw); return { s, e, d: (s.z + e.z) / 2 }; })
        .sort((p, q) => p.d - q.d);
      for (const line of lines) {
        ctx.globalAlpha = line.d < 0 ? 0.28 : 0.9;
        ctx.beginPath();
        ctx.moveTo(w / 2 + line.s.x * r, w / 2 - line.s.y * r);
        ctx.lineTo(w / 2 + line.e.x * r, w / 2 - line.e.y * r);
        ctx.stroke();
      }
      ctx.globalAlpha = 1;
    };
    const tick = (now: number) => { draw(now * 0.00018); frame = requestAnimationFrame(tick); };
    const start = () => { if (running || reduce.matches) return; running = true; frame = requestAnimationFrame(tick); };
    const stop = () => { running = false; cancelAnimationFrame(frame); draw(0.4); };

    size();
    draw(0.4);
    const resize = new ResizeObserver(() => { size(); if (!running) draw(0.4); });
    resize.observe(canvas);
    const visible = new IntersectionObserver(([entry]) => (entry.isIntersecting ? start() : stop()));
    visible.observe(canvas);
    const onMotion = () => (reduce.matches ? stop() : start());
    reduce.addEventListener('change', onMotion);
    return () => {
      stop();
      resize.disconnect();
      visible.disconnect();
      reduce.removeEventListener('change', onMotion);
    };
  }, []);

  return <canvas ref={ref} className="footer-wire" width={180} height={180} aria-hidden="true" />;
}
