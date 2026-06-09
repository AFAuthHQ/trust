import { html } from 'hono/html';

export function landingPage() {
  return html`
    <style>
      /* prominent hero call-to-action */
      .hero-cta { margin: 28px 0 4px; }
      .btn-cta {
        font-size: 17px; font-weight: 700; padding: 14px 30px; border-radius: 9px;
        box-shadow: 0 10px 24px rgba(184, 50, 39, 0.20);
        transition: transform 0.12s ease, box-shadow 0.12s ease;
      }
      .btn-cta:hover { transform: translateY(-1px); box-shadow: 0 12px 30px rgba(184, 50, 39, 0.28); }
      .hero-cta-note { display: block; margin-top: 12px; font-size: 13px; color: var(--muted); }
      .hero-cta-note b { color: var(--fg); font-weight: 600; }

      /* how-it-works framing */
      .seq-eyebrow {
        text-align: center; margin: 36px 0 0;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 11px; text-transform: uppercase; letter-spacing: 0.18em; color: var(--muted);
      }

      /* ===== sequence diagram: Agent · Trust · Service (blended into page) ===== */
      .seq-band {
        position: relative; left: 50%; transform: translateX(-50%);
        width: min(800px, calc(100vw - 32px)); margin: 10px 0 12px;
      }
      .seq-scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; }
      .seq {
        --c-agent: #5b54c9; --c-trust: #b83227; --c-service: #2f8f86;
        --c-once: #c2730f;
        min-width: 560px; background: transparent; padding: 2px 6px 4px;
      }

      .seq-head { display: grid; grid-template-columns: repeat(3, 1fr); margin-bottom: 4px; }
      .seq-actor {
        justify-self: center;
        display: inline-flex; align-items: center; gap: 6px;
        padding: 5px 13px; border-radius: 7px; border: 1.5px solid;
        font-family: 'IBM Plex Sans', ui-sans-serif, system-ui, -apple-system, sans-serif;
        font-weight: 700; font-size: 14px;
      }
      .seq-actor svg { width: 13px; height: 13px; display: block; }
      .seq-actor.agent { color: var(--c-agent); border-color: var(--c-agent); background: #edecfb; }
      .seq-actor.trust { color: var(--c-trust); border-color: var(--c-trust); background: #f8e5e2; }
      .seq-actor.service { color: #226f67; border-color: var(--c-service); background: #e2f1ef; }

      /* phase zones — one-time (manual) vs every-signup (automatic) */
      .seq-phase { position: relative; border-radius: 10px; padding: 2px 0 6px; }
      .seq-phase + .seq-phase { margin-top: 9px; }
      .seq-phase.once { background: rgba(194, 115, 15, 0.09); border: 1px solid rgba(194, 115, 15, 0.20); }
      .seq-phase.auto { background: rgba(47, 143, 134, 0.08); border: 1px solid rgba(47, 143, 134, 0.18); }
      .seq-tag {
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 10px; text-transform: uppercase; letter-spacing: 0.14em;
        padding: 5px 0 3px 12px; font-weight: 700;
      }
      .seq-phase.once .seq-tag { color: var(--c-once); }
      .seq-phase.auto .seq-tag { color: #226f67; }
      .seq-tag .reg { font-weight: 400; opacity: 0.7; letter-spacing: 0.04em; }

      .seq-life {
        position: absolute; top: 26px; bottom: 6px; width: 0;
        border-left: 1.5px solid var(--line); transform: translateX(-50%);
      }

      .seq-row { position: relative; height: 40px; }
      .seq-seg { position: absolute; top: 5px; height: 32px; }
      .seq-seg .lbl {
        position: absolute; top: 0; left: 0; right: 0;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 12.5px; color: var(--fg); white-space: nowrap;
      }
      .seq-seg .lbl b { color: var(--accent); font-weight: 700; }
      .seq-seg .ln { position: absolute; top: 19px; left: 0; right: 0; border-top: 2px solid var(--c); }
      .seq-seg.dash .ln { border-top-style: dashed; }
      .seq-seg .ln::after {
        content: ""; position: absolute; top: 0; width: 0; height: 0;
        border-top: 5px solid transparent; border-bottom: 5px solid transparent;
      }
      .seq-seg.r .ln::after { right: -1px; transform: translateY(-50%); border-left: 9px solid var(--c); }
      .seq-seg.l .ln::after { left: -1px; transform: translateY(-50%); border-right: 9px solid var(--c); }
      .seq-seg .sub {
        position: absolute; top: 23px; left: 0; right: 0;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 10.5px; color: var(--muted); white-space: nowrap;
      }
      .seq-seg.l .lbl, .seq-seg.l .sub { text-align: right; }
      .seq-seg.c-agent { --c: var(--c-agent); }
      .seq-seg.c-trust { --c: var(--c-trust); }
      .seq-seg.c-service { --c: var(--c-service); }

      .seq-row.note { height: 40px; }
      .seq-note {
        position: absolute; top: 4px; transform: translateX(-50%);
        background: rgba(255, 255, 255, 0.6); border: 1px solid rgba(20, 16, 8, 0.09);
        border-radius: 6px; padding: 6px 11px; max-width: 320px; text-align: center;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 11px; color: var(--muted); line-height: 1.35;
      }
      .seq-note .hu { color: var(--c-once); font-weight: 700; }
      .seq-note .ok { color: #2c6044; font-weight: 700; }

      .seq-caption { font-size: 14px; color: var(--fg); max-width: 66ch; margin: 12px auto 0; text-align: center; }
      .seq-caption b { color: var(--accent); }
      .seq-caption .muted { color: var(--muted); }

      /* value: two columns */
      .value-grid {
        display: grid; grid-template-columns: 1fr 1fr; gap: 30px;
        margin-top: 44px; padding-top: 30px; border-top: 1px solid var(--line);
      }
      .value-grid h2 { margin: 0 0 12px; font-size: 18px; }
      .value-grid ul { list-style: none; padding: 0; margin: 0; }
      .value-grid li { display: flex; gap: 11px; margin: 9px 0; font-size: 15px; line-height: 1.4; }
      .value-grid .ic { font-weight: 700; flex: 0 0 1em; }
      .value-grid .ic.ok { color: #2c6044; }
      .value-grid .ic.no { color: var(--accent); }

      .verif { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-top: 26px; }
      .verif-label {
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em;
        color: var(--muted); margin-right: 4px;
      }

      /* closing call-to-action */
      .close-cta {
        margin-top: 48px; padding: 28px; text-align: center;
        border-radius: 14px; background: rgba(184, 50, 39, 0.05);
        border: 1px solid rgba(184, 50, 39, 0.13);
      }
      .close-cta p { margin: 0 0 16px; font-size: 19px; color: var(--fg); }

      @media (prefers-reduced-motion: no-preference) {
        .seq-phase { opacity: 0; animation: seq-in 0.5s ease forwards; }
        .seq-phase.auto { animation-delay: 0.18s; }
        @keyframes seq-in { from { opacity: 0; transform: translateY(7px); } to { opacity: 1; transform: none; } }
      }
      @media (max-width: 600px) {
        .value-grid { grid-template-columns: 1fr; gap: 22px; }
      }
    </style>

    <h1 style="font-size: 40px; line-height: 1.1; margin: 0 0 16px;">
      A real human behind every agent.
    </h1>
    <p class="lede" style="font-size: 19px; max-width: 58ch;">
      Link your agent to you once. It can then prove a real person is behind it —
      so services grant real-user access (full free tier, no CAPTCHA) without ever
      seeing your email.
    </p>

    <div class="hero-cta">
      <a href="/signin" class="btn btn-primary btn-cta">Sign in to manage agents →</a>
      <span class="hero-cta-note">Free · sign in with email — <b>no service ever sees it</b></span>
    </div>

    <p class="seq-eyebrow">How it works</p>
    <div class="seq-band">
      <div class="seq-scroll">
        <div class="seq" role="img"
             aria-label="Sequence diagram with two zones. Zone one, done once: the agent asks the trust attestor to link it to its human, you sign in once, and the agent is linked. Zone two, automatic on every signup: the agent asks trust for proof of a human for the service, trust returns a 15-minute proof with no personal data, the agent presents it to the service, and the service grants the full free tier with no CAPTCHA.">
          <div class="seq-head">
            <div class="seq-actor agent">Agent</div>
            <div class="seq-actor trust">
              <svg viewBox="0 0 64 64" aria-hidden="true">
                <circle cx="24.5" cy="32" r="12.5" fill="none" stroke="#B83227" stroke-width="6"/>
                <circle cx="39.5" cy="32" r="12.5" fill="none" stroke="#15110A" stroke-width="6"/>
              </svg>
              Trust
            </div>
            <div class="seq-actor service">Service</div>
          </div>

          <!-- ZONE 1 — one time, manual -->
          <div class="seq-phase once">
            <div class="seq-tag">done once <span class="reg">— you approve it</span></div>
            <span class="seq-life" style="left: 16.667%;"></span>
            <span class="seq-life" style="left: 50%;"></span>
            <span class="seq-life" style="left: 83.333%;"></span>

            <div class="seq-row">
              <div class="seq-seg r c-agent" style="left: 16.667%; right: 50%;">
                <span class="lbl"><b>①</b> Link me to my human</span>
                <span class="ln"></span>
              </div>
            </div>
            <div class="seq-row note">
              <div class="seq-note" style="left: 50%;">
                <span class="hu">●</span> you sign in once · email, Google, or passkey
              </div>
            </div>
            <div class="seq-row">
              <div class="seq-seg l dash c-trust" style="left: 16.667%; right: 50%;">
                <span class="lbl">✓ linked to you</span>
                <span class="ln"></span>
              </div>
            </div>
          </div>

          <!-- ZONE 2 — every signup, automatic -->
          <div class="seq-phase auto">
            <div class="seq-tag">then, every signup <span class="reg">— fully automatic</span></div>
            <span class="seq-life" style="left: 16.667%;"></span>
            <span class="seq-life" style="left: 50%;"></span>
            <span class="seq-life" style="left: 83.333%;"></span>

            <div class="seq-row">
              <div class="seq-seg r c-agent" style="left: 16.667%; right: 50%;">
                <span class="lbl"><b>②</b> Need human proof · example.service</span>
                <span class="ln"></span>
              </div>
            </div>
            <div class="seq-row note">
              <div class="seq-note" style="left: 50%;">
                a 15-min proof · <span class="ok">no personal data</span>
              </div>
            </div>
            <div class="seq-row">
              <div class="seq-seg l dash c-trust" style="left: 16.667%; right: 50%;">
                <span class="lbl">proof: human ✓</span>
                <span class="ln"></span>
              </div>
            </div>
            <div class="seq-row">
              <div class="seq-seg r c-agent" style="left: 16.667%; right: 16.667%;">
                <span class="lbl"><b>③</b> Sign me up — here's my proof</span>
                <span class="ln"></span>
              </div>
            </div>
            <div class="seq-row">
              <div class="seq-seg l dash c-service" style="left: 16.667%; right: 16.667%;">
                <span class="lbl"><span style="color:#2c6044;font-weight:700;">✓</span> welcome — full free tier, no CAPTCHA</span>
                <span class="ln"></span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <p class="seq-caption">
      <b>Why the service can skip the CAPTCHA.</b> In step ③ it gets a short proof
      it can check on its own — proof that a real person approved this agent back in
      step ①. <span class="muted">So it opens the full free tier: no email, no
      profile, no bot-defense gauntlet.</span>
    </p>

    <div class="value-grid">
      <div class="value-col">
        <h2>What you control</h2>
        <ul>
          <li><span class="ic ok" aria-hidden="true">✓</span><span>Sign in once with email.</span></li>
          <li><span class="ic ok" aria-hidden="true">✓</span><span>See every linked agent in one place.</span></li>
          <li><span class="ic ok" aria-hidden="true">✓</span><span>Revoke any agent instantly — tokens expire within 15 minutes.</span></li>
        </ul>
      </div>
      <div class="value-col">
        <h2>What's not shared</h2>
        <ul>
          <li><span class="ic no" aria-hidden="true">✗</span><span>Services never see your email.</span></li>
          <li><span class="ic no" aria-hidden="true">✗</span><span>Services never see what other services you use.</span></li>
          <li><span class="ic no" aria-hidden="true">✗</span><span>Tokens carry &ldquo;verified human&rdquo; — nothing else.</span></li>
        </ul>
      </div>
    </div>

    <div class="verif">
      <span class="verif-label">Verification methods</span>
      <span class="pill pill-ok">email · live</span>
      <span class="pill pill-ok">oauth · live</span>
      <span class="pill pill-dim">payment · scaffolded</span>
    </div>

    <div class="close-cta">
      <p>Manage every agent that acts for you.</p>
      <a href="/signin" class="btn btn-primary btn-cta">Sign in to manage agents →</a>
    </div>
  `;
}
