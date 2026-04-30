#!/bin/sh
set -e

if [ -n "$JIRA_EMAIL" ]; then
    mkdir -p "$HOME/.config/.jira"
    sed "s/LOGIN_PLACEHOLDER/$JIRA_EMAIL/" /etc/vigil/jira-config.yml \
        > "$HOME/.config/.jira/.config.yml"
fi

exec vigil "$@"
