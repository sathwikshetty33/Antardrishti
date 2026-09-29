import { Download } from 'lucide-react'
import * as React from 'react'
import { Link } from 'react-router-dom'
import { PageHeader } from '@/components/AppShell'
import { CodeBlock } from '@/components/Code'
import { Card, CardContent } from '@/components/ui/card'

const repo = 'https://github.com/sathwikshetty33/Antardrishti'
const demoFiles = [
  { file: 'whatsapp.pcap.zst', size: '287 KB', what: 'a WhatsApp voice call replayed through an IKEv2 tunnel, handshake included (derived from ITC-Net-Audio-5, CC BY 4.0)' },
  { file: 'ikev1-aggressive.pcap.zst', size: '9.5 KB', what: 'IKEv1 aggressive mode with a pre-shared key, then pings (raises a high alert on its first chunk)' },
  { file: 'mixture.pcap.zst', size: '10 MB', what: 'voip, video and web in one transport-mode tunnel, captured mid-stream' },
]
const sections = [
  ['what', 'What live mode is'], ['where', 'Where to capture'], ['requirements', 'Requirements'], ['steps', 'Step by step'],
  ['sessions', 'Sessions and keys'], ['privacy', 'Privacy'], ['test-traffic', 'Generating test traffic'], ['troubleshooting', 'Troubleshooting'],
]

function H({ id, children }: { id: string; children: React.ReactNode }) {
  return <h2 id={id} className="mt-10 scroll-mt-20 border-b border-border pb-2 text-base font-semibold text-text">{children}</h2>
}

function Code({ children }: { children: React.ReactNode }) {
  return <code className="num rounded bg-surface-2 px-1 py-0.5 text-[12px] text-text">{children}</code>
}

// /docs/live-sensor: how to feed a live session from a machine that sees IPsec traffic
export function LiveSensorDocs() {
  const origin = window.location.origin
  const run = `sudo python3 antardrishti-agent.py --api ${origin} --session <session id> --key <sensor key> --iface <interface>`
  return (
    <>
      <PageHeader eyebrow={<Link to="/live" className="hover:text-text">Live sessions</Link>} title="Run a live sensor"
        description="Feed a live session from a machine that sees IPsec traffic, and watch the analysis build up chunk by chunk." />
      <div className="grid gap-8 xl:grid-cols-[220px_1fr]">
        <nav aria-label="On this page" className="hidden xl:block">
          <ol className="sticky top-20 space-y-1.5 text-xs">
            {sections.map(([id, t]) => <li key={id}><a href={`#${id}`} className="text-text-2 hover:text-text">{t}</a></li>)}
          </ol>
        </nav>
        <article className="min-w-0 max-w-3xl text-sm leading-relaxed text-text-2 [&_strong]:text-text">
          <H id="what">What live mode is</H>
          <p className="mt-3">
            A live session analyses IPsec traffic as it happens. A small agent, on a machine that sees the traffic, captures the
            outer packets and sends them here every 5 seconds. Each chunk is analysed as it arrives, so the tunnel's configuration,
            what is flowing inside it and the security findings build up while you watch. Nothing is decrypted: the agent sends
            the first 128 bytes of each ESP packet and the IKE handshake, which is all the analysis reads.
          </p>
          <p className="mt-3">
            No sensor yet? The <Link to="/live" className="text-accent hover:underline">demo sensor</Link> feeds a session a
            recorded capture through the same path, with nothing to install.
          </p>

          <H id="where">Where to capture</H>
          <Card className="mt-4 hover:translate-y-0"><CardContent className="pt-5"><Diagram /></CardContent></Card>
          <ol className="mt-4 list-decimal space-y-2 pl-5">
            <li><strong>A tap or SPAN (mirror) port</strong> on a switch the tunnel crosses: sees every tunnel on that link without touching either end.</li>
            <li><strong>The VPN gateway itself</strong> (strongSwan, libreswan, or any gateway with a shell and tcpdump): capture on its outside interface.</li>
            <li><strong>Your own machine running an IPsec VPN client</strong>: capture on the physical interface (Wi-Fi or Ethernet), not on the VPN's virtual one, which carries the decrypted side.</li>
          </ol>

          <H id="requirements">Requirements</H>
          <ul className="mt-3 list-disc space-y-1.5 pl-5">
            <li><strong>Linux or macOS</strong> with <strong>Python 3.8</strong> or newer, <strong>tcpdump</strong> and <strong>root</strong> (sudo). The agent uses the standard library only: no pip installs.</li>
            <li><strong>Windows:</strong> run it inside WSL2 (for example Ubuntu: <Code>sudo apt install python3 tcpdump</Code>). WSL2 sees its own virtual network, so run the VPN client or the test traffic inside WSL2 too.</li>
            <li>tcpdump: <Code>sudo apt install tcpdump</Code> (Debian, Ubuntu), <Code>sudo dnf install tcpdump</Code> (Fedora, RHEL); macOS ships it.</li>
            <li>Outbound HTTPS to this site.</li>
          </ul>

          <H id="steps">Step by step</H>
          <ol className="mt-3 list-decimal space-y-4 pl-5">
            <li>Create a session: on <Link to="/live" className="text-accent hover:underline">Live sessions</Link>, click <strong>Connect a sensor</strong> and give it a name if you like.</li>
            <li>Copy the <strong>sensor key</strong>. It is shown once: the server keeps only a hash of it. Copy the session link too.</li>
            <li>Download the agent:<CodeBlock className="mt-2" code={`curl -fsSLO ${origin}/agent/antardrishti-agent.py`} /></li>
            <li>
              Find the interface the encrypted traffic crosses:
              <CodeBlock className="mt-2" code="sudo python3 antardrishti-agent.py --list-ifaces" />
              <p className="mt-2 text-xs">Without <Code>--iface</Code> the agent uses the default-route interface on Linux. On macOS, pass it (for example <Code>--iface en0</Code>).</p>
            </li>
            <li>
              Run it, with your session's id and key:
              <CodeBlock className="mt-2" code={run} />
              <p className="mt-2 text-xs">It prints one line per chunk: the sequence number, the packets sent, the tunnels seen and the session's status. <Code>--chunk-seconds</Code> sets the chunk length, from 2 to 10 seconds (default 5).</p>
            </li>
            <li>Open the session link. The live view shows alerts as they are raised, the last 10 seconds of traffic, and the configuration and shares so far.</li>
            <li>Stop with <strong>Ctrl+C</strong>: the agent stops the session and exits. It also exits on its own when the session completes, printing why.</li>
          </ol>

          <H id="sessions">Sessions and keys</H>
          <ul className="mt-3 list-disc space-y-1.5 pl-5">
            <li><strong>Each run gets its own session</strong>, so runs never mix: their tunnels, findings and alerts stay apart.</li>
            <li><strong>A session's sensor key only lets a sensor feed that session</strong> (and stop it). Another session's key is refused.</li>
            <li><strong>All sessions are visible to everyone on the demo site</strong>: there are no accounts or workspaces. Send test traffic only.</li>
            <li>
              <strong>Limits</strong> (the defaults): a session completes after <strong>20 minutes</strong>, or once <strong>100 MB</strong> of
              ESP capture has built up, whichever comes first; at most <strong>1 chunk per second</strong>, of up to 3 MB; 3 active sessions
              per client. Every chunk re-analyses the session so far, which is why sessions are capped.
            </li>
            <li><strong>Auto-expiry:</strong> a session that receives no chunk for 20 minutes expires. A completed, stopped or expired session takes no more chunks: start a new one.</li>
          </ul>

          <H id="privacy">Privacy</H>
          <ul className="mt-3 list-disc space-y-1.5 pl-5">
            <li>Only <strong>ESP and AH headers</strong> (the first 128 bytes of each packet: the outer IP header, the ESP header and the start of the still-encrypted payload) and the <strong>IKE messages</strong> are sent. IKE_AUTH and the later exchanges are encrypted by IKE itself.</li>
            <li><strong>Nothing is decrypted</strong>, no key is needed or sent, and no other traffic on the interface is captured.</li>
            <li>The outer headers carry the tunnel's endpoint addresses, and these are shown to everyone who opens the session.</li>
          </ul>

          <H id="test-traffic">Generating test traffic</H>
          <p className="mt-3"><strong>An IPsec VPN client on that machine.</strong> Connect any IKEv2 or IKEv1 VPN (strongSwan on Linux, the built-in IKEv2 VPN on macOS), then run the agent on the physical interface. WireGuard and OpenVPN are not IPsec, so they show nothing.</p>
          <p className="mt-4"><strong>A sample capture, looped with tcpreplay through a veth pair</strong> (Linux or WSL2). The samples are Linux cooked captures, so they get Ethernet headers first:</p>
          <CodeBlock className="mt-2" code={[
            'sudo apt install tcpreplay zstd',
            `curl -fsSLO ${repo}/raw/main/app/api/demo/whatsapp.pcap.zst`,
            'zstd -d whatsapp.pcap.zst',
            'tcprewrite --dlt=enet --enet-smac=02:00:00:00:00:01 --enet-dmac=02:00:00:00:00:02 \\',
            '  --infile=whatsapp.pcap --outfile=whatsapp-eth.pcap',
            'sudo ip link add antar0 type veth peer name antar1',
            'sudo ip link set antar0 up && sudo ip link set antar1 up',
            'sudo tcpreplay --intf1=antar0 --loop=0 whatsapp-eth.pcap',
          ].join('\n')} />
          <p className="mt-3">In a second terminal, run the agent on the other end of the pair, then remove the pair when you are done:</p>
          <CodeBlock className="mt-2" code={[
            `sudo python3 antardrishti-agent.py --api ${origin} --session <session id> --key <sensor key> --iface antar1`,
            'sudo ip link del antar0',
          ].join('\n')} />
          <p className="mt-4">The sample captures (test-split runs of the project's dataset):</p>
          <ul className="mt-2 space-y-2">
            {demoFiles.map((d) => (
              <li key={d.file} className="flex items-start gap-2">
                <Download className="mt-1 size-3.5 shrink-0 text-accent" aria-hidden />
                <span><a href={`${repo}/raw/main/app/api/demo/${d.file}`} className="num text-accent hover:underline">{d.file}</a> ({d.size}): {d.what}</span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs">Attribution for the WhatsApp capture: <a href={`${repo}/blob/main/app/api/demo/README.md`} className="text-accent hover:underline">app/api/demo/README.md</a>.</p>

          <H id="troubleshooting">Troubleshooting</H>
          <dl className="mt-3 space-y-3">
            {([
              ['"must run as root", or permission denied', 'Run the agent with sudo: tcpdump needs raw sockets.'],
              ['"tcpdump was not found on PATH"', 'Install tcpdump (see Requirements) and try again.'],
              ['No tunnels seen (0 packets or 0 tunnels per chunk)', 'The agent is on the wrong interface: list them with --list-ifaces and pick the one the encrypted traffic crosses, the physical one rather than the VPN\'s virtual one. Or the VPN is WireGuard or OpenVPN rather than IPsec, which has no ESP or IKE to see.'],
              ['"could not determine the default interface"', 'On macOS (or without a default route) pass --iface.'],
              ['403: the sensor key does not match', 'The key belongs to another session, or is mistyped: each session has its own key. If the key is lost, create a new session.'],
              ['413: the chunk is over the 3 MB limit', 'Too much traffic for one chunk. Use a lower --chunk-seconds (down to 2).'],
              ['Session completed or expired (410)', 'A session completes at 20 minutes or 100 MB of ESP capture, and expires after 20 minutes without a chunk; either way it takes no more chunks. Create a new session.'],
            ] as const).map(([k, v]) => (
              <div key={k} className="rounded-lg border border-border px-4 py-3">
                <dt className="font-medium text-text">{k}</dt>
                <dd className="mt-1 text-xs">{v}</dd>
              </div>
            ))}
          </dl>
        </article>
      </div>
    </>
  )
}

// where a sensor can sit: a tap on the path, the gateway, or the client machine
function Diagram() {
  const box = 'fill-[var(--surface-2)] stroke-[var(--border-strong)]'
  const label = 'fill-[var(--text)] text-[12px]'
  const sub = 'fill-[var(--text-2)] text-[11px]'
  const pin = (x: number, y: number, n: number) => (
    <g>
      <circle cx={x} cy={y} r={11} className="fill-[var(--accent)]" />
      <text x={x} y={y + 4} textAnchor="middle" className="fill-[var(--accent-ink)] text-[12px] font-semibold">{n}</text>
    </g>
  )
  return (
    <svg viewBox="0 0 720 250" className="h-auto w-full" role="img"
      aria-label="A VPN client and a VPN gateway joined by an IPsec tunnel. A sensor can sit at a tap or SPAN port on the link (1), on the gateway (2) or on the client machine (3). It sends ESP headers and IKE messages over HTTPS, every 5 seconds, to Antardrishti, whose live view shows the analysis.">
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0,0 L10,5 L0,10 z" className="fill-[var(--accent)]" />
        </marker>
      </defs>
      <rect x="10" y="30" width="170" height="54" rx="10" className={box} />
      <text x="95" y="54" textAnchor="middle" className={label}>VPN client</text>
      <text x="95" y="72" textAnchor="middle" className={sub}>laptop or router</text>
      <rect x="400" y="30" width="180" height="54" rx="10" className={box} />
      <text x="490" y="54" textAnchor="middle" className={label}>VPN gateway</text>
      <text x="490" y="72" textAnchor="middle" className={sub}>strongSwan, libreswan</text>
      <line x1="180" y1="57" x2="400" y2="57" className="stroke-[var(--accent)]" strokeWidth={3} />
      <text x="290" y="47" textAnchor="middle" className={sub}>IPsec tunnel: IKE + ESP</text>
      <line x1="580" y1="57" x2="630" y2="57" className="stroke-[var(--border-strong)]" strokeWidth={2} strokeDasharray="4 4" />
      <text x="675" y="61" textAnchor="middle" className={sub}>network</text>
      {pin(290, 78, 1)}
      <text x="290" y="106" textAnchor="middle" className={sub}>tap / SPAN port</text>
      {pin(490, 18, 2)}
      {pin(95, 18, 3)}
      <rect x="190" y="150" width="210" height="54" rx="10" className={box} />
      <text x="295" y="174" textAnchor="middle" className={label}>sensor</text>
      <text x="295" y="192" textAnchor="middle" className={sub}>the agent + tcpdump</text>
      <line x1="290" y1="118" x2="295" y2="148" className="stroke-[var(--border-strong)]" strokeWidth={1.5} strokeDasharray="3 3" />
      <rect x="505" y="150" width="200" height="54" rx="10" className="fill-[var(--accent-soft)] stroke-[var(--accent)]" />
      <text x="605" y="174" textAnchor="middle" className={label}>Antardrishti</text>
      <text x="605" y="192" textAnchor="middle" className={sub}>API + live view</text>
      <line x1="400" y1="177" x2="503" y2="177" className="stroke-[var(--accent)]" strokeWidth={2} markerEnd="url(#arrow)" />
      <text x="452" y="226" textAnchor="middle" className={sub}>HTTPS, a chunk every 5 s</text>
      <text x="452" y="242" textAnchor="middle" className={sub}>ESP headers + IKE only</text>
    </svg>
  )
}
