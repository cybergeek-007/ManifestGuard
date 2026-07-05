# Continuous Integration

The ready-to-use CI pipeline lives in [`ci.yml`](./ci.yml).

## Activating it

GitHub blocks automated tools from creating files under `.github/workflows/`
without special permissions, so the workflow is stored here instead. To enable
it, copy it into place and push (from your own machine, which has workflow
permission):

```bash
mkdir -p .github/workflows
cp ci/ci.yml .github/workflows/ci.yml
git add .github/workflows/ci.yml
git commit -m "Enable CI workflow"
git push
```

Alternatively, create the file directly in the GitHub UI
(**Add file → Create new file → `.github/workflows/ci.yml`**) and paste the
contents of `ci/ci.yml`.

## What it runs

- **Backend:** `python -m compileall backend` + `python -m unittest tests.test_engines`
- **Frontend:** `npm ci` + `tsc --noEmit` + `vite build`

Both jobs run on every push and pull request.
