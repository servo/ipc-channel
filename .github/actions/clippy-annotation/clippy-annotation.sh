#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

annotations=$(jq -r '
  select(.reason == "compiler-message")
  | .message as $msg
  | select($msg.level == "error" or $msg.level == "warning")
  | $msg.spans[]
  | select(.is_primary)
  | "::\($msg.level) file=\(.file_name),line=\(.line_start),col=\(.column_start)\(if .column_end != .column_start then ",endColumn=\(.column_end)" else "" end)::\($msg.message)"
')

# Print the annotations
if [[ -n "$annotations" ]]; then
  echo "$annotations"
  exit 1
fi
