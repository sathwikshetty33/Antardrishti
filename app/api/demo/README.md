# Demo captures

Three small test-split captures from the Antardrishti dataset, built by `python -m
app.api.demo.make` from kept runs (the router's outer capture with the full IKE packets merged
in). They load with one click in the UI and drive the replay.

| file | run | what it shows |
|---|---|---|
| `mixture.pcap.zst` | `p1-voip_video_web-21e3e3f0-r1` | voip, video and web in one transport-mode tunnel, captured mid-stream (no IKE setup in the capture) |
| `whatsapp.pcap.zst` | `p1-whatsapp-40244c69-r1` | a WhatsApp voice call replayed through an IKEv2 tunnel |
| `ikev1-aggressive.pcap.zst` | `p0-e14-c468d4c1-r1` | edge case e14: IKEv1 aggressive mode with a pre-shared key |

The lab traffic is the project's own. The WhatsApp capture is derived from **ITC-Net-Audio-5**
(M. Nikbakht and M. Teimouri, ITC Laboratory, University of Tehran, figshare 2024,
doi:10.6084/m9.figshare.24721035.v2), used under the Creative Commons Attribution 4.0
International licence (https://creativecommons.org/licenses/by/4.0/). Changes: the call's
addresses were rewritten to the lab's, it was replayed through the lab's IPsec tunnel and
captured again; this file holds that new capture (encrypted ESP), not the original. The
original authors do not endorse this project.
