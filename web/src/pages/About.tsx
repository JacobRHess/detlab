export default function About() {
  return (
    <article className="md" style={{ maxWidth: 760 }}>
      <h1>About detlab</h1>
      <p>
        Most public Sigma repos give you a rule and call it done. <strong>detlab</strong> answers
        the question <em>"how do you know it actually works?"</em> by shipping each detection
        alongside the attack that produces it, the captured telemetry, and the tests that prove
        the rule fires positive and stays quiet on benign traffic.
      </p>

      <h2>What this site is</h2>
      <p>
        A static, zero-install tour of the <a href="https://github.com/JacobRHess/detlab" target="_blank" rel="noreferrer">detlab repository</a>.
        Every page is generated from <code>cases/</code> in the source tree, so the rule, the
        Sigma, the fixtures, and the playground all reflect what actually lands in CI.
      </p>
      <p>
        The detector playground runs the real Python detection logic in your browser via
        <a href="https://pyodide.org" target="_blank" rel="noreferrer"> Pyodide</a> — the same
        function CI calls, on the same fixtures, with no server in the loop.
      </p>

      <h2>What this site is not</h2>
      <p>
        It is not a hosted Splunk. The production artifact is the deployable Splunk app
        (<code>build/detlab-&lt;version&gt;.tar.gz</code>) you can install into your own Splunk
        instance. This site is the front door — the rules, the rationale, and a way to
        sanity-check the detection without spinning up Docker.
      </p>

      <h2>How to use detlab</h2>
      <ol>
        <li>Browse the coverage matrix on the home page.</li>
        <li>Open a shipped case to see the attack, the SPL, the Sigma, and the fixtures.</li>
        <li>Click <em>Try the detector</em> to run the production detection logic on the bundled fixture.</li>
        <li>Want it in your SIEM? Grab the <a href="https://github.com/JacobRHess/detlab/releases" target="_blank" rel="noreferrer">.spl release</a> or fork the case folder.</li>
      </ol>

      <h2>Stack</h2>
      <ul>
        <li>Detection content: SPL macros, Sigma YAML, Zeek log fixtures.</li>
        <li>Spec mirror: Python 3.11+, stdlib only — runs in CI and in-browser unchanged.</li>
        <li>Site: Vite + React + TypeScript, no backend, deployed to GitHub Pages.</li>
        <li>Lab runtime: docker-compose with Splunk + Zeek + Suricata.</li>
      </ul>

      <h2>License</h2>
      <p>MIT. Use it, fork it, ship better detections.</p>
    </article>
  );
}
