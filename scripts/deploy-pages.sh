#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

pnpm run build

deploy_dir=$(mktemp -d)
cleanup() {
  rm -rf "$deploy_dir"
}
trap cleanup EXIT

cp -a dist/. "$deploy_dir/"
touch "$deploy_dir/.nojekyll"

remote_url=$(git remote get-url origin)
cd "$deploy_dir"
git init --quiet
git checkout -b gh-pages >/dev/null
git config user.name "$(git -C "$repo_root" config user.name || echo 'David Carliez')"
git config user.email "$(git -C "$repo_root" config user.email || echo 'david.carliezz@gmail.com')"
git add -A
git commit -m "Deploy site" >/dev/null
git remote add origin "$remote_url"
git push -f origin gh-pages
