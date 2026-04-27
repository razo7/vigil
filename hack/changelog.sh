#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?Usage: changelog.sh VERSION BUILD_NUMBER SHORT_SHA}"
BUILD_NUMBER="${2:?Usage: changelog.sh VERSION BUILD_NUMBER SHORT_SHA}"
SHORT_SHA="${3:?Usage: changelog.sh VERSION BUILD_NUMBER SHORT_SHA}"

OUTFILE="docs/changelog-v${VERSION}-${BUILD_NUMBER}.md"
COMMIT_COUNT=$(git rev-list --count HEAD)
RANGE_SIZE=10
DATE=$(date -u +%Y-%m-%d)

# Find the base commit (10 commits ago)
BASE_SHA=$(git rev-list --skip="${RANGE_SIZE}" --max-count=1 HEAD)
if [ -z "${BASE_SHA}" ]; then
    BASE_SHA=$(git rev-list --max-parents=0 HEAD)
fi
BASE_SHORT=$(git rev-parse --short "${BASE_SHA}")

PREV_BUILD=$(( BUILD_NUMBER - 1 ))
if [ "${PREV_BUILD}" -gt 0 ]; then
    PREV_TAG="v${VERSION}-${PREV_BUILD}"
else
    PREV_TAG="(initial)"
fi

mkdir -p docs

{
    echo "# Vigil v${VERSION}-${BUILD_NUMBER} -- Build Changelog"
    echo ""
    IMAGE_TAG="v${VERSION}-${BUILD_NUMBER}-${SHORT_SHA}"
    echo "**Image:** [\`quay.io/oraz/vigil:${IMAGE_TAG}\`](https://quay.io/repository/oraz/vigil?tab=tags&tag=${IMAGE_TAG})"
    echo "**Date:** ${DATE}"
    echo "**Commits:** ${BASE_SHORT}..${SHORT_SHA} (${RANGE_SIZE} commits)"
    echo "**Previous image:** ${PREV_TAG}"
    echo ""

    # Highlights section: group commits by conventional prefix or directory
    echo "## Highlights"
    echo ""

    # Collect unique subject prefixes and notable changes
    NEW_FILES=$(git diff --diff-filter=A --name-only "${BASE_SHA}..HEAD" | head -20)
    DELETED_FILES=$(git diff --diff-filter=D --name-only "${BASE_SHA}..HEAD" | head -20)

    # Feature commits (add/new/introduce)
    FEATURES=$(git log --oneline "${BASE_SHA}..HEAD" --grep="[Aa]dd\|[Nn]ew\|[Ii]ntroduce\|[Ii]mplement" --format="- %s" 2>/dev/null || true)
    if [ -n "${FEATURES}" ]; then
        echo "### New"
        echo ""
        echo "${FEATURES}"
        echo ""
    fi

    # Fix commits
    FIXES=$(git log --oneline "${BASE_SHA}..HEAD" --grep="[Ff]ix\|[Bb]ug\|[Rr]esolve\|[Rr]epair" --format="- %s" 2>/dev/null || true)
    if [ -n "${FIXES}" ]; then
        echo "### Fixes"
        echo ""
        echo "${FIXES}"
        echo ""
    fi

    # CI/infra commits
    CI_CHANGES=$(git log --oneline "${BASE_SHA}..HEAD" --grep="CI\|workflow\|container\|docker\|tag\|build\|Makefile\|Reduce\|push" --format="- %s" 2>/dev/null || true)
    if [ -n "${CI_CHANGES}" ]; then
        echo "### CI / Infrastructure"
        echo ""
        echo "${CI_CHANGES}"
        echo ""
    fi

    # New directories
    if [ -n "${NEW_FILES}" ]; then
        NEW_DIRS=$(echo "${NEW_FILES}" | xargs -I{} dirname {} | sort -u | while read -r d; do
            if ! git ls-tree -d "${BASE_SHA}" -- "${d}" >/dev/null 2>&1; then
                echo "${d}"
            fi
        done || true)
        if [ -n "${NEW_DIRS}" ]; then
            echo "### New packages"
            echo ""
            echo "${NEW_DIRS}" | while read -r d; do
                count=$(echo "${NEW_FILES}" | grep -c "^${d}/" 2>/dev/null || echo 0)
                echo "- \`${d}/\` (${count} files)"
            done
            echo ""
        fi
    fi

    # Commits table
    echo "## Commits"
    echo ""
    echo "| SHA | Subject |"
    echo "|-----|---------|"
    git log --format="| [\`%h\`](https://github.com/razo7/vigil/commit/%h) | %s |" "${BASE_SHA}..HEAD"
    echo ""

    # Files changed summary
    echo "## Files Changed"
    echo ""
    STAT=$(git diff --stat "${BASE_SHA}..HEAD" | tail -1)
    echo "${STAT}"
    echo ""

    # By area
    echo "### By area"
    echo ""
    git diff --name-only "${BASE_SHA}..HEAD" | while read -r f; do
        if [[ "${f}" == */* ]]; then
            dirname "${f}"
        else
            echo "(root)"
        fi
    done | sort | uniq -c | sort -rn | while read -r count dir; do
        if [ "${dir}" = "(root)" ]; then
            echo "- root -- ${count} files"
        else
            echo "- \`${dir}/\` -- ${count} files"
        fi
    done
    echo ""

    # Deleted files
    if [ -n "${DELETED_FILES}" ]; then
        echo "### Removed"
        echo ""
        echo "${DELETED_FILES}" | while read -r f; do
            echo "- \`${f}\`"
        done
        echo ""
    fi

} > "${OUTFILE}"

echo "Changelog written to ${OUTFILE}"
