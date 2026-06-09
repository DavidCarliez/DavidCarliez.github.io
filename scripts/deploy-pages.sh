#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

npm run build

deploy_dir=$(mktemp -d)
cleanup() {
  rm -rf "$deploy_dir"
}
trap cleanup EXIT

cp -a dist/. "$deploy_dir/"
touch "$deploy_dir/.nojekyll"

git --git-dir="$repo_root/.git" --work-tree="$deploy_dir" add -A
git --git-dir="$repo_root/.git" --work-tree="$deploy_dir" commit -m "Deploy site" || true
git --git-dir="$repo_root/.git" --work-tree="$deploy_dir" branch -M gh-pages
git --git-dir="$repo_root/.git" --work-tree="$deploy_dir" push -f origin gh-pages

git checkout -B main origin/main >/dev/null 2>&1 || true
