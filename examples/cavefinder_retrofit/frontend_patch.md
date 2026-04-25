# Cavefinder Frontend Patch Snippets

The cavefinder SPA (React 18) currently renders its own `/login`, `/register`,
and `/forgot-password` pages. In the retrofit those routes either redirect
to the IdP or disappear entirely. These snippets are drop-in.

## 1. Remove the old auth forms

Delete:
```
src/pages/Login.jsx
src/pages/Register.jsx
src/pages/ForgotPassword.jsx
src/pages/VerifyEmail.jsx
```

And their routes in `src/App.jsx`.

## 2. Keep the route stubs (bookmark preservation)

Users have `/login` bookmarked. Replace the page components with one-liner
redirects so those URLs still work:

```jsx
// src/pages/LoginRedirect.jsx
import { useEffect } from "react";

export default function LoginRedirect() {
  useEffect(() => {
    const returnTo = encodeURIComponent(window.location.origin + "/");
    window.location.replace(`${import.meta.env.VITE_CAVEID_ISSUER}/login?return=${returnTo}`);
  }, []);
  return <p>Redirecting to CaveFinder ID…</p>;
}
```

`src/App.jsx`:
```jsx
<Route path="/login" element={<LoginRedirect />} />
<Route path="/register" element={<RegisterRedirect />} />
<Route path="/forgot-password" element={<ForgotPasswordRedirect />} />
```

`RegisterRedirect` and `ForgotPasswordRedirect` are copies of `LoginRedirect`
pointing to `/register` and `/forgot-password` on the IdP respectively.

## 3. `useCurrentUser` hook — switch to IdP /userinfo

Old hook fetched `/api/auth/me` and decoded the session cookie itself.
New hook calls the proxy in `auth_blueprint.py`, which forwards the cookie
to the IdP:

```jsx
// src/hooks/useCurrentUser.js
import { useEffect, useState } from "react";

export function useCurrentUser() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/auth/userinfo", { credentials: "include" })
      .then((r) => (r.ok ? r.json() : null))
      .then((u) => { if (!cancelled) setUser(u); })
      .catch(() => { if (!cancelled) setUser(null); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  return { user, loading };
}
```

The cookie is `__Secure-cf_at` on `Domain=.cavefinder.app`, so the browser
automatically attaches it for any same-site request — no token management
in JS.

## 4. Log out button

Was a DELETE to `/api/auth/session`. Now POSTs to the thin proxy which
forwards to the IdP's `/logout`:

```jsx
async function logOut() {
  await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
  window.location.assign("/");
}
```

## 5. Account-settings link

The old `/settings` page read/wrote locally. Replace with an external link
to the IdP's `/account` page:

```jsx
<a href={`${import.meta.env.VITE_CAVEID_ISSUER}/account`}>
  Account settings →
</a>
```

Nothing identity-related stays on cavefinder.

## 6. Vite env

`frontend/.env.production`:
```
VITE_CAVEID_ISSUER=https://id.cavefinder.app
```

## 7. Handling 401 from `/api/*` calls

Any API call that returns 401 now means "session expired at the IdP" —
the user needs to re-auth. Central interceptor:

```jsx
// src/lib/api.js
export async function apiFetch(path, opts = {}) {
  const resp = await fetch(path, { credentials: "include", ...opts });
  if (resp.status === 401) {
    const returnTo = encodeURIComponent(window.location.href);
    window.location.assign(
      `${import.meta.env.VITE_CAVEID_ISSUER}/login?return=${returnTo}`
    );
    // never resolves
    return new Promise(() => {});
  }
  return resp;
}
```

Use `apiFetch` everywhere in place of `fetch` for `/api/*` calls.
