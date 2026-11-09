// Passkeys (WebAuthn): sign in on /login, add one on /account; the supplier portal uses the same buttons with its
// own URLs in data- attributes (/s/login, /s/account). The server sends the options as JSON with base64url bytes
// and checks everything (cem_auth/passkeys.py); this file only bridges.
(() => {
  const b64 = {
    dec: s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0)).buffer,
    enc: b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  };
  const ids = list => (list || []).map(d => ({ ...d, id: b64.dec(d.id) }));
  const creation = o => ({ ...o, challenge: b64.dec(o.challenge), user: { ...o.user, id: b64.dec(o.user.id) }, excludeCredentials: ids(o.excludeCredentials) });
  const request = o => ({ ...o, challenge: b64.dec(o.challenge), allowCredentials: ids(o.allowCredentials) });
  const asJSON = c => {
    const r = c.response, out = { id: c.id, rawId: b64.enc(c.rawId), type: c.type, clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {}, authenticatorAttachment: c.authenticatorAttachment || null, response: { clientDataJSON: b64.enc(r.clientDataJSON) } };
    if (r.attestationObject) {
      out.response.attestationObject = b64.enc(r.attestationObject);
      out.response.transports = r.getTransports ? r.getTransports() : [];
    } else {
      out.response.authenticatorData = b64.enc(r.authenticatorData);
      out.response.signature = b64.enc(r.signature);
      if (r.userHandle) out.response.userHandle = b64.enc(r.userHandle);
    }
    return out;
  };
  const post = async (url, body) => {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body === undefined ? '{}' : JSON.stringify(body), credentials: 'same-origin' });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || 'Something went wrong. Try again.');
    return j;
  };
  const say = (el, msg) => { if (el) { el.textContent = msg; el.hidden = !msg; } };
  const cancelled = e => e && (e.name === 'NotAllowedError' || e.name === 'AbortError');

  const signIn = document.getElementById('passkey-signin');
  if (signIn) {
    if (!window.PublicKeyCredential) signIn.hidden = true;
    signIn.addEventListener('click', async () => {
      const err = document.getElementById('passkey-err');
      say(err, '');
      signIn.disabled = true;
      try {
        const url = signIn.dataset.url || '/login/passkey';
        const opts = await post(url + '/options');
        const cred = await navigator.credentials.get({ publicKey: request(opts) });
        const done = await post(url, asJSON(cred));
        location.assign(done.next || '/');
      } catch (e) {
        say(err, cancelled(e) ? '' : e.message);
      } finally {
        signIn.disabled = false;
      }
    });
  }

  const add = document.getElementById('passkey-add');
  if (add) {
    if (!window.PublicKeyCredential) { add.disabled = true; say(document.getElementById('passkey-err'), 'This browser cannot make passkeys.'); }
    add.addEventListener('click', async () => {
      const err = document.getElementById('passkey-err');
      say(err, '');
      add.disabled = true;
      try {
        const url = add.dataset.url || '/account/passkeys';
        const opts = await post(url + '/options');
        const cred = await navigator.credentials.create({ publicKey: creation(opts) });
        const name = document.getElementById('passkey-name').value;
        await post(url, { credential: asJSON(cred), name });
        location.assign((add.dataset.done || '/account') + '?msg=' + encodeURIComponent('Passkey added. Next time, tap "Sign in with a passkey".'));
      } catch (e) {
        say(err, e && e.name === 'InvalidStateError' ? 'This device already has a passkey for your account.' : cancelled(e) ? '' : e.message);
      } finally {
        add.disabled = false;
      }
    });
  }
})();
