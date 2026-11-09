# Recording the demo

`docs/demo.gif` was made by running the shot list below in a headless browser (one with no
window), using the real extension and popup, the local test page and the public badssl.com test
site. The Steam store artwork is blurred. If the interface changes, re-record it by hand.

The goal is a 20–30 second GIF that shows the incident's lure being caught: a fake Steam sign-in
page graded F, with the brand-impersonation and fake-login findings. Save it as `docs/demo.gif`;
the README already shows it.

## Setup

1. Serve the repository folder:

   ```bash
   python -m http.server 8000 --bind 127.0.0.1
   ```

2. Give your own machine a name other than localhost, because localhost is skipped by the page
   checks. `steam-gift-card.127.0.0.1.nip.io` works without admin rights: the public nip.io DNS
   service points it at `127.0.0.1`, so the page never leaves your machine. (Alternatively, add
   `127.0.0.1  steam-gift-card.test` to your hosts file as administrator.)

3. Load the extension: `chrome://extensions` → Developer mode → Load unpacked → this folder.
   Pin the SentinelQA icon to the toolbar.

## Shot list

1. Open `https://store.steampowered.com` and click the icon. You should see a good grade (A or
   B, depending on the headers Steam sends that day). This shows it isn't a blanket alarm.
2. Open `http://steam-gift-card.127.0.0.1.nip.io:8000/test-fake-login.html`, click the icon: F.
   Hold for a few seconds on the findings: no HTTPS, brand name in an unrelated domain, brand +
   reward lure, password over HTTP, and "presenting itself as Steam … likely a fake login page".
3. Optional: open `https://self-signed.badssl.com`, click through the warning, and show the
   certificate error finding (the symptom of an "evil twin" fake Wi-Fi hotspot).

## Recording

- Windows: ScreenToGif (record a region, trim, export as GIF at 10–15 fps, about 800 px wide).
- macOS: Kap. Linux: Peek.
- Keep the file under about 5 MB so GitHub shows it inline.

Use only the bundled test page. Don't record real phishing sites or real accounts.
