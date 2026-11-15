# AerolVM code interpreter driver for Bash.
#
# One process is one context: a bash in which cd, variables and functions
# persist between runs. It speaks the frame protocol in
# internal/codeinterp/doc.go, "fd" mode only (toolboxd). Needs bash 4.4 or
# newer: {fd} allocation, "local -" and ${!name@a}.
#
# Written for AerolVM (MIT). No code is taken from Daytona or E2B.

if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ] ||
	{ [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 4 ]; }; then
	__aerol_msg="bash 4.4 or newer is required (found ${BASH_VERSION:-unknown})"
	printf 'FATAL %d\n%s' "${#__aerol_msg}" "$__aerol_msg" >&4
	echo "aerolvm interpreter driver: $__aerol_msg" >&2
	exit 1
fi

if [ "${AEROL_INTERP_MODE:-}" != fd ]; then
	echo "aerolvm interpreter driver: bash runs only in fd mode" >&2
	exit 1
fi

# The protocol descriptors move above 9 and 3 and 4 close: scripts use
# "exec 3>file" freely, and that must not cut the context off. Private
# copies of fd 1 and 2 carry the markers, so they still reach the host's
# pipes after the user's "exec >file".
if ! exec {__aerol_req}<&3 {__aerol_ev}>&4 {__aerol_out}>&1 {__aerol_err}>&2 3<&- 4>&-; then
	echo "aerolvm interpreter driver: protocol descriptors 3 and 4 are not open" >&2
	exit 1
fi
__aerol_nonce=${AEROL_INTERP_NONCE:-}
unset AEROL_INTERP_MODE AEROL_INTERP_NONCE

__aerol_seq=0
__aerol_count=0
__aerol_int=0
__aerol_env=()
__aerol_saved=()

# Every helper starts with "local -; set +eu": the user's set -e or set -u
# in a cell must not end the context inside the driver's own code. builtin
# keeps a user function named printf or read from replacing the driver's.

__aerol_emit() {
	local -
	set +eu
	# Byte lengths: the host counts bytes, and LC_ALL=C makes ${#2} do so.
	local LC_ALL=C
	builtin printf '%s %d\n%s' "$1" "${#2}" "$2" >&"$__aerol_ev"
}

# __aerol_sync orders the user's output before the next frame (doc.go):
# the marker on both output pipes, then SYNC with its number.
__aerol_sync() {
	local -
	set +eu
	__aerol_seq=$((__aerol_seq + 1))
	local mark=$'\x1e'"$__aerol_nonce:$__aerol_seq"$'\x1e'
	builtin printf '%s' "$mark" >&"$__aerol_out" 2>/dev/null
	builtin printf '%s' "$mark" >&"$__aerol_err" 2>/dev/null
	__aerol_emit SYNC "$__aerol_seq"
}

# __aerol_read reads one frame into __aerol_kind and __aerol_payload.
__aerol_read() {
	local -
	set +eu
	# Inside this function only: read -n then counts bytes, not characters.
	# The user's code keeps the context's own locale.
	local LC_ALL=C header= part n want chunk st
	while :; do
		IFS= builtin read -r part <&"$__aerol_req"
		st=$?
		header+=$part
		((st == 0)) && break
		# Above 128 a trapped signal cut the read short; anything else is
		# the end of the request stream.
		((st > 128)) || return 1
	done
	__aerol_kind=${header%% *}
	n=${header#* }
	[[ $n =~ ^[0-9]+$ ]] || return 1
	__aerol_payload=
	while ((n > 0)); do
		want=$n
		# NUL is the delimiter so that a NUL byte, which a bash string
		# cannot hold, is still counted: read stops at it and consumes it.
		IFS= builtin read -r -d '' -n "$want" chunk <&"$__aerol_req"
		st=$?
		__aerol_payload+=$chunk
		n=$((n - ${#chunk}))
		if ((st == 0)); then
			((${#chunk} < want)) && n=$((n - 1))
		elif ((st <= 128)); then
			return 1
		fi
	done
	return 0
}

# __aerol_next waits for the next EXEC and prepares it. It returns non-zero
# when the context should end.
__aerol_next() {
	local -
	set +eu
	while __aerol_read; do
		case $__aerol_kind in
		QUIT) return 1 ;;
		ENV) __aerol_env+=("$__aerol_payload") ;;
		EXEC)
			__aerol_code=$__aerol_payload
			__aerol_begin
			return 0
			;;
		esac
	done
	return 1
}

__aerol_begin() {
	local -
	set +eu
	__aerol_count=$((__aerol_count + 1))
	__aerol_int=0
	__aerol_saved=()
	local pair name
	for pair in "${__aerol_env[@]}"; do
		name=${pair%%=*}
		# Only names a shell variable can have; __aerol_ ones are the
		# driver's.
		[[ $name =~ ^[A-Za-z_][A-Za-z0-9_]*$ && $name != __aerol_* && $pair == *=* ]] || continue
		# Saved as: name, set or not, value, attributes.
		if [[ ${!name+set} ]]; then
			__aerol_saved+=("$name" 1 "${!name}" "${!name@a}")
		else
			__aerol_saved+=("$name" 0 "" "")
		fi
		builtin export "$name=${pair#*=}"
	done
	__aerol_env=()
	__aerol_emit COUNT "$__aerol_count"
}

# __aerol_restore puts the variables an ENV frame changed back, last saved
# first so a name sent twice ends at its value from before the run.
__aerol_restore() {
	local -
	set +eu
	local i name
	for ((i = ${#__aerol_saved[@]} - 4; i >= 0; i -= 4)); do
		name=${__aerol_saved[i]}
		# A name the cell made readonly cannot go back; its error would
		# only confuse, since the cell already ended.
		if [[ ${__aerol_saved[i + 1]} == 1 ]]; then
			builtin printf -v "$name" '%s' "${__aerol_saved[i + 2]}" 2>/dev/null
			[[ ${__aerol_saved[i + 3]} == *x* ]] || builtin export -n "$name" 2>/dev/null
		else
			builtin unset -v "$name" 2>/dev/null
		fi
	done
	__aerol_saved=()
}

# An interrupt during a run unwinds it: with extdebug, a DEBUG trap that
# returns 2 makes the function or sourced file running the next command
# return. That ends busy loops of builtins too, and the rest of the cell.
__aerol_on_int() {
	__aerol_int=1
	builtin trap '__aerol_unwind' DEBUG
}

__aerol_unwind() {
	case ${FUNCNAME[1]-main} in
	main | __aerol_*) return 0 ;;
	esac
	return 2
}

__aerol_finish() {
	local -
	set +eu
	local status=$1
	builtin trap '' INT
	builtin trap - DEBUG
	__aerol_restore
	if [[ $__aerol_int == 1 ]]; then
		__aerol_sync
		__aerol_emit DONE interrupted
	elif [[ $status != 0 ]]; then
		# A failed last command is the run's error, as in a notebook's
		# bash kernel: no name, the exit status as the value.
		__aerol_sync
		__aerol_emit ERROR $'\x1f'"$status"$'\x1f'
		__aerol_sync
		__aerol_emit DONE error
	else
		__aerol_sync
		__aerol_emit DONE ok
	fi
	__aerol_int=0
}

# The DEBUG trap stays with functions and subshells only under extdebug,
# and only extdebug turns its status 2 into a return.
shopt -s extdebug
# SIGINT is ignored between runs: the host only interrupts runs, and a
# stray one must not end the context or cut a frame read short.
trap '' INT

__aerol_emit READY 1

# The cell is sourced: it runs in this shell, so cd, variables and declare
# stay (a function would make declare local), and "return" ends it. Source
# does not hide this loop from the cell's "break" and "continue", so the
# one-pass for loop takes them: the cell just ends there. A "break 2" or
# more still ends the context.
while __aerol_next; do
	trap '__aerol_on_int' INT
	for __aerol_once in 1; do
		. <(builtin printf '%s\n' "$__aerol_code")
	done
	__aerol_finish "$?"
done
exit 0
