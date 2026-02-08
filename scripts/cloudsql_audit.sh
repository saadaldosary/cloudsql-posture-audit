#!/usr/bin/env bash
set -Eeuo pipefail

# Cloud SQL posture audit (fast JSON fetch + local evaluation)
# Requirements: gcloud, jq, column (bsdmainutils/util-linux)
#
# Usage:
#   ./cloudsql_audit.sh                         # current project
#   ./cloudsql_audit.sh -p my-project           # specific project
#   ./cloudsql_audit.sh --all-projects          # all accessible projects
#   ./cloudsql_audit.sh --csv out.csv           # export CSV
#
# Notes:
# - Skips projects where sqladmin API is disabled.
# - Findings are heuristic-based (good for security posture reviews).

RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; BLU=$'\e[34m'; DIM=$'\e[2m'; RST=$'\e[0m'

PROJECTS=()
ALL_PROJECTS=false
CSV_OUT=""
NO_COLOR=false

die() { echo "${RED}ERROR:${RST} $*" >&2; exit 1; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<EOF
Usage:
  $0 [options]

Options:
  -p, --project <id>     Audit a specific project (can repeat)
      --all-projects     Audit all accessible projects
      --csv <file>       Write CSV output
      --no-color         Disable colors
  -h, --help             Show help

Examples:
  $0
  $0 -p my-prod-project
  $0 --all-projects --csv cloudsql_findings.csv
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--project) PROJECTS+=("${2:-}"); shift 2 ;;
    --all-projects) ALL_PROJECTS=true; shift ;;
    --csv) CSV_OUT="${2:-}"; shift 2 ;;
    --no-color) NO_COLOR=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown arg: $1" ;;
  esac
done

$NO_COLOR && { RED=""; YEL=""; GRN=""; BLU=""; DIM=""; RST=""; }

has_cmd gcloud || die "gcloud not found. Install Google Cloud SDK."
has_cmd jq || die "jq not found. Install jq."
has_cmd column || echo "${YEL}WARN:${RST} 'column' not found. Table output may be less pretty."

if $ALL_PROJECTS; then
  mapfile -t PROJECTS < <(gcloud projects list --format="value(projectId)" 2>/dev/null || true)
  [[ ${#PROJECTS[@]} -gt 0 ]] || die "No projects found (or no permission)."
fi

if [[ ${#PROJECTS[@]} -eq 0 ]]; then
  # default to current project
  CURR_PROJ="$(gcloud config get-value project 2>/dev/null || true)"
  [[ -n "$CURR_PROJ" ]] || die "No project set. Run: gcloud config set project <PROJECT_ID>"
  PROJECTS+=("$CURR_PROJ")
fi

check_api_enabled() {
  local project="$1"
  # Using services list avoids calling sqladmin when disabled
  gcloud services list --enabled --project "$project" --format="value(config.name)" 2>/dev/null \
    | grep -q '^sqladmin.googleapis.com$'
}

json_or_empty="[]"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

rows_tsv="$tmp_dir/rows.tsv"
rows_csv="$tmp_dir/rows.csv"
: > "$rows_tsv"
: > "$rows_csv"

# Header (TSV/CSV)
header="project\tinstance\tregion\tengine\tversion\tedition\ttier\tdisk_gb\tha\treplicas\tbackups\tpitr\tpublic_ip\tauth_nets\trequire_ssl\tdel_protect\tfindings"
echo -e "$header" >> "$rows_tsv"
echo "project,instance,region,engine,version,edition,tier,disk_gb,ha,replicas,backups,pitr,public_ip,auth_nets,require_ssl,del_protect,findings" >> "$rows_csv"

total_projects=0
scanned_projects=0
skipped_projects=0
total_instances=0

hi_non_ha=0
hi_public=0
hi_no_backups=0
hi_no_ssl=0
hi_no_delprot=0

for project in "${PROJECTS[@]}"; do
  ((total_projects++)) || true
  echo "${BLU}==>${RST} Project: ${project}"

  if ! check_api_enabled "$project"; then
    echo "  ${DIM}- Skipping: Cloud SQL Admin API (sqladmin.googleapis.com) is not enabled${RST}"
    ((skipped_projects++)) || true
    continue
  fi

  ((scanned_projects++)) || true

  inst_json="$tmp_dir/${project}.instances.json"
  if ! gcloud sql instances list --project "$project" --format=json > "$inst_json" 2>/dev/null; then
    echo "  ${YEL}- Could not list instances (permission/region issues). Skipping project.${RST}"
    continue
  fi

  # If no instances, continue
  inst_count="$(jq 'length' "$inst_json" 2>/dev/null || echo 0)"
  if [[ "$inst_count" == "0" ]]; then
    echo "  - No Cloud SQL instances"
    continue
  fi

  # Build TSV rows in jq (fast, single pass)
  # Findings rules:
  # - NON_HA if availabilityType != REGIONAL
  # - PUBLIC if ipv4Enabled true OR has a PUBLIC ipAddress
  # - NO_BACKUPS if backupEnabled not true
  # - NO_PITR if pointInTimeRecoveryEnabled not true (if field exists; else "n/a")
  # - NO_SSL if requireSsl not true (if field exists; else "n/a")
  # - NO_DEL_PROT if deletionProtectionEnabled not true
  # - AUTH_NETS if public and authorized networks present (still a risk depending)
  jq -r --arg project "$project" '
    def boolstr: if . == true then "yes" elif . == false then "no" else "n/a" end;

    .[] | (
      .name as $name
      | (.region // "n/a") as $region
      | (.databaseVersion // "n/a") as $dbv
      | ($dbv | split("_")[0]) as $engine
      | ($dbv | if contains("_") then (split("_") | .[1]) else "n/a" end) as $version
      | (.settings.edition // .settings.databaseEdition // "n/a") as $edition
      | (.settings.tier // "n/a") as $tier
      | (.settings.dataDiskSizeGb // "n/a") as $disk
      | (.settings.availabilityType // "n/a") as $haType
      | (if $haType == "REGIONAL" then "HA" elif $haType == "ZONAL" then "Zonal" else $haType end) as $ha

      | ((.replicaNames // []) | length) as $replicas

      | ((
          .settings.backupConfiguration
          // .settings.backupConfigurations
          // []
        ) as $bcs
        | (
            ($bcs | map(.enabled) | any(. == true)) as $backupEnabled
            | ($bcs | map(.pointInTimeRecoveryEnabled) | any(. == true)) as $pitrEnabled
            | ($backupEnabled | boolstr) as $backups
            | (if ($bcs | map(has("pointInTimeRecoveryEnabled")) | any(. == true)) then ($pitrEnabled | boolstr) else "n/a" end) as $pitr
            | [$backups, $pitr]
          )
        ) as $bp

      | ($bp[0]) as $backups
      | ($bp[1]) as $pitr

      | (.settings.ipConfiguration // {}) as $ipcfg
      | (($ipcfg.ipv4Enabled // false) == true) as $ipv4Enabled
      | ((.ipAddresses // []) | map(.type) | any(. == "PRIMARY")) as $hasPrimary
      | ((.ipAddresses // []) | map(.type) | any(. == "PUBLIC")) as $hasPublicType
      | ((.ipAddresses // []) | map(.ipAddress) | any(. != null)) as $hasAnyIp

      | ( ($ipv4Enabled or $hasPublicType) ) as $public
      | (if $public then "yes" else "no" end) as $publicIp

      | ($ipcfg.authorizedNetworks // []) as $auth
      | (if ($auth | length) > 0 then ($auth | map(.value // .name // "net") | join("|")) else "-" end) as $authNets

      | ($ipcfg.requireSsl) as $reqSslRaw
      | (if ($ipcfg | has("requireSsl")) then ($reqSslRaw | boolstr) else "n/a" end) as $requireSsl

      | (.settings.deletionProtectionEnabled | boolstr) as $delProt

      | ([
          (if $ha != "HA" then "NON_HA" else empty end),
          (if $public then "PUBLIC_IP" else empty end),
          (if $backups != "yes" then "NO_BACKUPS" else empty end),
          (if $pitr == "no" then "NO_PITR" else empty end),
          (if $requireSsl == "no" then "NO_SSL" else empty end),
          (if $delProt != "yes" then "NO_DEL_PROTECT" else empty end),
          (if $public and $authNets != "-" then "AUTH_NETS_SET" else empty end)
        ] | join(";")
      ) as $findings

      | [$project, $name, $region, $engine, $version, $edition, $tier, $disk, $ha, ($replicas|tostring), $backups, $pitr, $publicIp, $authNets, $requireSsl, $delProt, (if $findings == "" then "OK" else $findings end)]
      | @tsv
    )
  ' "$inst_json" >> "$rows_tsv"

  # Also write CSV rows from TSV (simple conversion, escaping is minimal here)
  tail -n +2 "$rows_tsv" | awk -F'\t' 'BEGIN{OFS=","} {for(i=1;i<=NF;i++){gsub(/"/,"\"\"",$i); if($i ~ /[,\n"]/){$i="\"" $i "\""}} print}' >> "$rows_csv"

  # Count instances and high-risk categories (from TSV lines written for this project)
  proj_lines="$(grep -c "^${project}\t" "$rows_tsv" || true)"
  ((total_instances += proj_lines)) || true

  # Update counters based on findings text
  while IFS=$'\t' read -r p inst region engine ver edition tier disk ha reps backups pitr public auth ssl del findings; do
    [[ "$p" == "project" ]] && continue
    [[ "$p" != "$project" ]] && continue

    [[ "$findings" == *"NON_HA"* ]] && ((hi_non_ha++)) || true
    [[ "$findings" == *"PUBLIC_IP"* ]] && ((hi_public++)) || true
    [[ "$findings" == *"NO_BACKUPS"* ]] && ((hi_no_backups++)) || true
    [[ "$findings" == *"NO_SSL"* ]] && ((hi_no_ssl++)) || true
    [[ "$findings" == *"NO_DEL_PROTECT"* ]] && ((hi_no_delprot++)) || true
  done < "$rows_tsv"

done

echo
echo "${BLU}==== Summary ====${RST}"
echo "Projects total     : $total_projects"
echo "Projects scanned   : $scanned_projects"
echo "Projects skipped   : $skipped_projects (Cloud SQL API disabled)"
echo "Instances found    : $total_instances"
echo
echo "${YEL}High-signal findings counts:${RST}"
echo "  NON_HA           : $hi_non_ha"
echo "  PUBLIC_IP        : $hi_public"
echo "  NO_BACKUPS       : $hi_no_backups"
echo "  NO_SSL           : $hi_no_ssl"
echo "  NO_DEL_PROTECT   : $hi_no_delprot"
echo

echo "${BLU}==== Detailed Table ====${RST}"
if has_cmd column; then
  cat "$rows_tsv" | column -t -s $'\t'
else
  cat "$rows_tsv"
fi

if [[ -n "$CSV_OUT" ]]; then
  cp "$rows_csv" "$CSV_OUT"
  echo
  echo "${GRN}CSV written:${RST} $CSV_OUT"
fi
