#!/usr/bin/bash
# Synthetic manager receipts for launcher tests. This fixture never calls systemctl.
set -eu
command=${2:-}
unit=${!#}
units=$HOME/.config/systemd/user
stage=${XDG_DATA_HOME:-$HOME/.local/share}/oc-sandbox/bridge-stage
load=not-found
if [[ -f $units/$unit || $unit == "${STUB_BRIDGE_LOADED:-}" ]]; then load=loaded; fi

case $command in
  enable)
    [[ -z ${STUB_BRIDGE_ENABLE_FAIL:-} ]]
    ;;
  stop)
    [[ -z ${STUB_BRIDGE_STAYS_ACTIVE:-} ]]
    ;;
  is-enabled)
    if [[ $unit == "${STUB_BRIDGE_STILL_ENABLED:-}" ]]; then
      printf '%s\n' "${STUB_BRIDGE_ENABLEMENT:-enabled}"
      exit 0
    fi
    if [[ $load == loaded ]]; then printf 'disabled\n'; exit 1; fi
    printf 'not-found\n'
    exit 4
    ;;
  show)
    [[ -z ${STUB_BRIDGE_MANAGER_FAIL:-} ]] || exit 1
    if [[ $unit == --property=UnitPath ]]; then
      printf 'UnitPath=%s\n' "$units ${STUB_BRIDGE_GLOBAL_UNITS:-$units}"
      exit 0
    fi
    fragment= dropin= triggers= active=inactive job= wanted=
    if [[ $load == loaded ]]; then
      fragment="$units/$unit"
      if [[ $unit == "${STUB_BRIDGE_WRONG_FRAGMENT:-}" ]]; then fragment="/foreign/$unit"; fi
      if [[ $unit == "${STUB_BRIDGE_DROPIN:-}" ]]; then dropin=/foreign/override.conf; fi
      if [[ $unit == *.timer || $unit == *.path ]]; then triggers=oc-bridge.service; fi
    fi
    if [[ -n ${STUB_BRIDGE_STAYS_ACTIVE:-} ]]; then active=active; fi
    if [[ $unit == "${STUB_BRIDGE_ACTIVE_TIMER:-}" ]] &&
       ! grep -Fqx "systemctl --user stop $unit" "${OC_TEST_BRIDGE_LOG:-/dev/null}"; then active=active; fi
    if [[ $unit == "${STUB_BRIDGE_PENDING:-}" ]]; then job=9; fi
    if [[ $unit == "${STUB_BRIDGE_DEPENDENCY:-}" ]]; then wanted=default.target; fi
    if [[ ${3:-} == --property=LoadState ]]; then
      printf 'LoadState=%s\nActiveState=%s\nJob=%s\n' "$load" "$active" "$job"
      exit 0
    fi
    printf 'Id=%s\nLoadState=%s\nActiveState=%s\nJob=%s\nFragmentPath=%s\nDropInPaths=%s\n' \
      "$unit" "$load" "$active" "$job" "$fragment" "$dropin"
    printf 'Triggers=%s\nTriggeredBy=\nWantedBy=%s\nRequiredBy=\nUpheldBy=\n' "$triggers" "$wanted"
    if [[ $unit == oc-bridge.service && $load == loaded ]]; then
      runner=$HOME/.local/bin/oc-bridge
      printf 'Type=oneshot\nExecStart={ path=%s ; argv[]=%s ; ignore_errors=no ; pid=0 }\n' "$runner" "$runner"
      printf 'ExecStartPre=\nExecStartPost=\nExecStop=%s\nExecStopPost=\nExecReload=\nExecCondition=\n' \
        "${STUB_BRIDGE_STOP_HOOK:-}"
      printf 'Environment=OC_SB="%s" OC_BRIDGE_STAGE="%s"\n' \
        "$HOME/opencode-sandbox" "${STUB_BRIDGE_STAGE:-$stage}"
      printf 'EnvironmentFiles=\nPassEnvironment=\nUnsetEnvironment=\n'
    fi
    ;;
esac
