# P1 CPD Hub on Netlify

The CPD Hub as a Netlify site: the pages are static files in `public/`, and one Netlify Function (`netlify/functions/api.mjs`) handles sign-in, records and certificate files. Records and PDFs are stored in **Netlify Blobs**, Netlify's built-in storage, so there's no separate database to set up.

- Advisers: `https://YOUR-SITE.netlify.app/`
- Admin: `https://YOUR-SITE.netlify.app/#admin`

## Set it up (all in the browser)

### 1. Put the files on GitHub
1. Sign in to GitHub and create a **new private repository**, e.g. `p1-cpd-hub`. Tick nothing else.
2. On the empty repository page, choose **uploading an existing file**.
3. Unzip the download on your computer, open the `p1-cpd-hub-netlify` folder, select **everything inside it** (`netlify.toml`, `package.json`, `README.md`, and the `netlify` and `public` folders) and drag it onto the GitHub page.
4. Click **Commit changes**.

Check that `netlify.toml` sits at the top level of the repository, not inside another folder.

### 2. Create the Netlify site
1. In Netlify, choose **Add new site → Import an existing project → GitHub**, allow access, and pick the repository.
2. Leave the build settings as they are. They come from `netlify.toml`.
3. Before deploying, open **Environment variables** (or **Site configuration → Environment variables** after the first deploy) and add:

| Variable | Value |
|---|---|
| `ADMIN_PASSWORD` | A long password for the admin area (at least 10 characters). Share it only with the people who issue certificates. |
| `SESSION_SECRET` | A random string of at least 32 characters, e.g. from your password manager's generator. Never share it. Changing it signs everyone out. |

4. Deploy. If you added the variables after the first deploy, go to **Deploys → Trigger deploy** so the function picks them up.

### 3. Move your existing data across
1. In the internal hub on claude.ai, go to **Advisers → Backup and move data → Export all data**. Save the zip.
2. Open `https://YOUR-SITE.netlify.app/#admin`, sign in with `ADMIN_PASSWORD`.
3. Go to **Advisers → Import from backup** and choose the zip. Keep the page open until it says it's finished.
4. Sign in as an adviser at the main address to check their certificates are there.

Running the import twice is safe: anything already imported is skipped.

### 4. Optional: your own web address
In Netlify, **Domain management → Add a domain**, e.g. `cpd.p1investmentservices.co.uk`. Netlify shows the DNS record IT needs to add. HTTPS is set up automatically.

## Updating the site later
Upload the changed files to the same GitHub repository (same folders, same names) and commit. Netlify redeploys automatically within a minute or two. Your data is not affected by redeploys.

## Settings you can add later

| Variable | Default | What it does |
|---|---|---|
| `LOGIN_MODE` | `email` | `code` emails advisers a 6-digit code before they can sign in. Needs the SMTP settings below. Recommended before sharing the link widely. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_SECURE`, `MAIL_FROM` | | Email sending for login codes, e.g. a Microsoft 365 mailbox or a sending service. |
| `SESSION_DAYS` | `30` | How long an adviser stays signed in |
| `ADMIN_SESSION_HOURS` | `12` | How long an admin stays signed in |

## Limits to know about
- **Email-only sign-in:** anyone who knows an adviser's email address can see that adviser's certificates. Switch `LOGIN_MODE` to `code` when you can.
- **One shared admin password:** there are no individual admin accounts. Change `ADMIN_PASSWORD` (and redeploy) when someone leaves.
- **File size:** each certificate or background file must be under 5.5 MB, because Netlify Functions limit request size.
- **Rate limiting** of sign-in attempts is per server instance, so it slows down guessing but isn't a hard block.
- **Plan limits and data location:** check your Netlify plan's limits for function calls and Blobs storage, and where Netlify stores the data, against your data protection requirements. CPD records contain advisers' names and email addresses.
