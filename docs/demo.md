# Recording the demo

`docs/demo.gif` was produced from a headless browser run of the shot list below (the real
extension and popup, local test page, public badssl.com test site; the Steam store artwork is
blurred). Re-record by hand with the steps below if the UI changes.

Goal: a 20–30 second GIF showing the incident's lure being caught — a fake Steam sign-in page
graded F with the brand-impersonation and fake-login findings. Save it as `docs/demo.gif` and
uncomment the image line in the README.

## Setup

1. Serve the repository folder:

   ```bash
   python -m http.server 8000 --bind 127.0.0.1
   ```

2. Use a non-localhost name for your own machine (localhost is exempt from page checks).
   `steam-gift-card.127.0.0.1.nip.io` works without admin rights: the public nip.io DNS
   service resolves it to `127.0.0.1`, so the page never leaves your machine. (Alternative: add
   `127.0.0.1  steam-gift-card.test` to your hosts file as administrator.)

3. Load the extension: `chrome://extensions` → Developer mode → Load unpacked → this folder.
   Pin the SentinelQA icon to the toolbar.

## Shot list

1. Open `https://store.steampowered.com`, click the icon → a good grade (A or B,
   depending on the headers Steam sends that day). Shows it is not a blanket alarm.
2. Open `http://steam-gift-card.127.0.0.1.nip.io:8000/test-fake-login.html`, click the icon → grade F.
   Hold for a few seconds on the findings: no HTTPS, brand name in an unrelated domain, brand +
   reward lure, password over HTTP, and "presenting itself as Steam … likely a fake login page".
3. Optional: `https://self-signed.badssl.com` → click through the warning → certificate error
   finding (the evil-twin Wi-Fi symptom).

## Recording

- Windows: ScreenToGif (record region → trim → export GIF, 10–15 fps, ~800 px wide).
- macOS: Kap. Linux: Peek.
- Keep the file under ~5 MB so GitHub renders it inline.

Use only the bundled test page; do not record real phishing sites or real accounts.
