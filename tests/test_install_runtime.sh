#!/usr/bin/env bash
# Runs only extracted dependency/runtime checks with shell mocks. Never runs the installer.
set -Eeuo pipefail

TEST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="$TEST_DIR/../install.sh"
TASK_TMP_PARENT="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)"
TASK_TMP="$(mktemp -d "$TASK_TMP_PARENT/aws-audit-runtime-test.XXXXXXXX")"
TASK_TMP="$(cd -- "$TASK_TMP" && pwd -P)"
cleanup() {
  # Resolve and check the absolute target before recursive removal, including on MSYS.
  case "$TASK_TMP" in
    "$TASK_TMP_PARENT"/aws-audit-runtime-test.*)
      [[ ! -d $TASK_TMP ]] || rm -rf -- "$TASK_TMP" ;;
    *) printf 'Refusing cleanup outside the test temp directory: %s\n' "$TASK_TMP" >&2; return 1 ;;
  esac
}
trap cleanup EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# Exercise the installed code rather than maintaining a second copy of its package lists.
awk '
  /^if \(\(INSTALL_DEPS\)\); then$/ { capture=1; starts++ }
  /^for dependency in / { if (capture) { ended=1; exit } }
  capture { print }
  END { if (starts != 1 || !ended) exit 1 }
' "$INSTALLER" > "$TASK_TMP/packages.sh" || fail 'dependency block markers changed'
[[ -s $TASK_TMP/packages.sh ]] || fail 'dependency block was not found'

# The runtime check must precede frontend checkout and npm bootstrap.
awk '
  /^# Verify downloaded Node before cloning sources or invoking npm\.$/ { capture=1; starts++; next }
  /^# End Node runtime preflight\.$/ { if (capture) { ended=1; exit } }
  capture { print }
  END { if (starts != 1 || !ended) exit 1 }
' "$INSTALLER" > "$TASK_TMP/runtime.sh" || fail 'Node preflight markers changed'
grep -q 'node' "$TASK_TMP/runtime.sh" || fail 'Node preflight is missing before frontend checkout'
awk '
  /^# End Node runtime preflight\.$/ { preflight=NR }
  /^if \[\[ -z \$WEB_SOURCE \]\]; then$/ {
    if (!preflight || preflight >= NR) exit 1
    found=1; exit
  }
  END { if (!found) exit 1 }
' "$INSTALLER" || fail 'Node preflight must precede frontend checkout'

run_packages() (
  selected_manager="$1"
  INSTALL_DEPS="${2:-1}"
  command() {
    case "${1:-} ${2:-}" in
      '-v apt-get') [[ $selected_manager == apt ]] ;;
      '-v dnf') [[ $selected_manager == dnf ]] ;;
      '-v yum') [[ $selected_manager == yum ]] ;;
      *) builtin command "$@" ;;
    esac
  }
  apt-get() { printf '%s\n' "$@" >> "$TASK_TMP/packages.log"; }
  dnf() { printf '%s\n' "$@" >> "$TASK_TMP/packages.log"; }
  yum() { printf '%s\n' "$@" >> "$TASK_TMP/packages.log"; }
  source "$TASK_TMP/packages.sh"
)

for manager in apt dnf yum; do
  : > "$TASK_TMP/packages.log"
  run_packages "$manager"
  if [[ $manager == apt ]]; then
    for package in libatomic1 libstdc++6; do
      grep -Fxq "$package" "$TASK_TMP/packages.log" || fail "$manager omitted $package"
    done
  else
    for package in libatomic libstdc++; do
      grep -Fxq "$package" "$TASK_TMP/packages.log" || fail "$manager omitted $package"
    done
  fi
  printf 'PASS: %s installs Node runtime libraries\n' "$manager"
done

: > "$TASK_TMP/packages.log"
run_packages apt 0
[[ ! -s $TASK_TMP/packages.log ]] || fail '--no-deps unexpectedly called a package manager'
printf 'PASS: --no-deps skips OS package installation\n'

run_runtime() (
  # Keep errexit active in this independently executed subshell, not an if condition.
  set -e
  NODE_VERSION=v24.0.0
  node() {
    printf 'node %s\n' "$*" >> "$TASK_TMP/runtime.log"
    if [[ $1 == --version && $runtime_node_status != 0 ]]; then
      printf 'node: error while loading shared libraries: libatomic.so.1: cannot open shared object file\n' >&2
      return "$runtime_node_status"
    fi
    printf 'v24.0.0\n'
  }
  npm() { printf 'npm %s\n' "$*" >> "$TASK_TMP/runtime.log"; }
  git() { printf 'git %s\n' "$*" >> "$TASK_TMP/runtime.log"; }
  go() { printf 'go %s\n' "$*" >> "$TASK_TMP/runtime.log"; }
  source "$TASK_TMP/runtime.sh"
  # Sentinels represent the real operations that follow the extracted preflight.
  git clone mock-frontend
  npm install mock-package-manager
)

: > "$TASK_TMP/runtime.log"
runtime_node_status=127
set +e
run_runtime > "$TASK_TMP/runtime-failure.out" 2>&1
runtime_status=$?
set -e
[[ $runtime_status != 0 ]] || fail 'broken Node did not stop installation'
grep -q '^node --version$' "$TASK_TMP/runtime.log" || fail 'Node executable was not probed'
if grep -Eq '^(git|npm) ' "$TASK_TMP/runtime.log"; then
  fail 'broken Node reached frontend checkout or npm bootstrap'
fi
grep -q 'libatomic.so.1' "$TASK_TMP/runtime-failure.out" || fail 'Node loader diagnostic was lost'
printf 'PASS: missing libatomic aborts before checkout/npm\n'

: > "$TASK_TMP/runtime.log"
runtime_node_status=0
run_runtime > "$TASK_TMP/runtime-success.out" 2>&1
grep -q '^git clone mock-frontend$' "$TASK_TMP/runtime.log" || fail 'healthy Node blocked subsequent work'
grep -q '^npm install mock-package-manager$' "$TASK_TMP/runtime.log" || fail 'healthy Node blocked npm'
printf 'PASS: healthy Node permits subsequent installation\n'
