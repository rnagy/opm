#!/bin/sh
#
# Copyright (c) 2018 Robert Nagy <robert@openbsd.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

set -e
umask 077

OPM_STORE=${OPM_STORE:-${HOME}/.opm/store}
OPM_KEYSTORE=${OPM_KEYSTORE:-${HOME}/.opm/private}
_CBOARD=primary
_CLIP=0
_ML=0
_KEYRING=0

[ -d ${OPM_STORE} ] || mkdir -p ${OPM_STORE}
[ -d ${OPM_KEYSTORE} ] || mkdir -p ${OPM_KEYSTORE}

trap_handler()
{
	set +e # we're trapped
	rm -f "${_TMP}"
}

opm_debug()
{
	[ -z ${_DEBUG} ] || echo "===> ${1}" || true
}

opm_err()
{
	echo "${1}" 1>&2 && return ${2:-1}
}

usage()
{
	cat << USAGE
usage: ${0##*/}	[-bcdhkm] [-C clipboard] [-p file] [-s file] [-P file]
		[-S file] command
USAGE
	exit 1
}

make_temp()
{
	_TMP=$(mktemp -p ${OPM_STORE} .XXXXXXXXXX)
}

strip_name()
{
	while read _path; do
		_path=${_path%%.sig}
		_path=${_path##${OPM_STORE}/}
		_path=${_path##${OPM_STORE}}
		print "${_path}"
	done
}

find_sig()
{
	find ${OPM_STORE} -name '*.sig' -print 2>/dev/null | strip_name
}

search()
{
	local _path=$1
	find_sig | grep -Gie "${_path}"
}

verify()
{
	local _e
	for _e in $(find_sig); do
		opm_debug "Verifying ${_e} with ${_SPUBLIC_KEY}"
		signify -Vq -p ${_SPUBLIC_KEY} -m ${OPM_STORE}/${_e} || \
			opm_err "unable to verify ${_e}"
	done
}

encrypt()
{
	local _path=$1
	local _e
	if [ -z ${_path} ]; then
		for _e in $(find_sig); do
			encrypt ${_e} ${OPM_STORE}/${_e}
		done
	else
		[ -f ${OPM_STORE}/${_path} ] || opm_err "Non-existent entry"
		show_entry ${_path} > ${_TMP} && do_encrypt ${_path}
	fi
}

tree()
{
	[ -z ${_BATCH} ] && \
		awk '!/\.$/ {for (i=1;i<NF-1;i++){printf("|   ")} \
			print "|-- "$NF}' FS='/' && \
				return
	while read _e; do
		print "${_e##./}"
	done
}

show_list()
{
	for _f in $(cd ${OPM_STORE} && find . -name '*.sig' 2>/dev/null); do
		if [ -z ${_BATCH} ]; then
			_d=${_f%/*}
			until [[ ${_d} == '.' ]]; do
				_p="${_d} ${_p}"
				_d=${_d%/*}
			done
			for _pe in ${_p}; do
				[[ " ${_pd[*]} " == *" $_pe "* ]] || \
					echo ${_pe} | tree && \
						_pd="${_pd} ${_pe}"
			done
		fi
		echo ${_f} | sed "s,.sig$,,g" | tree
	done
}

do_encrypt()
{
	local _path=$1
	local _parent="${_path%/*}"
	local _recipients=${_PUBLIC_KEY}
	[ -d ${OPM_STORE}/${_parent}/.team ] && \
		_recipients="${_PUBLIC_KEY} \
			$(ls ${OPM_STORE}/${_parent}/.team/*.pub)"

	for _k in ${_recipients}; do
		_cn=$(openssl x509 -noout -subject -in ${_k} | \
			sed -n '/^subject/s/^.*CN=//p')
		opm_debug "Encrypting ${OPM_STORE}/${_path} for ${_cn}"
	done
	openssl smime -encrypt -aes256 -in ${_TMP} -out ${OPM_STORE}/${_path} \
		-outform PEM ${_recipients}
	echo "Signing ${OPM_STORE}/${_path} with ${_SPRIVATE_KEY}"
	signify -S -s ${_SPRIVATE_KEY} -m ${OPM_STORE}/${_path} || \
		rm -f ${OPM_STORE}/${_path}
}

add_entry()
{
	local _path=$1
	local _parent="${_path%/*}"
	[ -z ${_path} ] && opm_err "Empty path"
	[[ ${_parent} == ${_path} ]] && opm_err "Empty group"
	[[ ${_parent} == ${_path%/} ]] && opm_err "Empty file"
	[ -d "${OPM_STORE}/${_parent}" ] || mkdir -p "${OPM_STORE}/${_parent}"

	if [ ${_ML} -gt 0 ]; then
		${EDITOR:-vi} ${_TMP}
	else
		if [ -t 0 ]; then
			stty -echo
			printf '%s' "Enter password for ${_path}: "
			IFS= read -r _pw
			printf '\n%s' "Retype password for ${_path}: "
			IFS= read -r _rpw
			stty echo
			printf '\n'
		fi
		[ -z "${_pw}" -o -z "${_rpw}" ] && opm_err "Empty password"
		[ "${_pw}" != "${_rpw}" ] && opm_err "Password mismatch"
		printf '%s' "${_pw}" > ${_TMP}
	fi
	do_encrypt ${_path}
}

path_check()
{
	local _path=$1
	local _abs=$(readlink -f "${OPM_STORE}/${_path}" 2>/dev/null)
	[[ "$_abs" == "${OPM_STORE}"* ]] || opm_err "invalid path"
}

del_entry()
{
	local _path=$1
	[ -f ${OPM_STORE}/${_path} ] || opm_err "Non-existent entry"
	rm -i ${OPM_STORE}/${_path}
	[ -e ${OPM_STORE}/${_path} ] || \
		echo rm -f ${OPM_STORE}/${_path}.sig
}

show_entry()
{
	local _e
	local _path=$1
	local _parent="${_path%/*}"
	[ -z ${_path} ] && opm_err "Empty path"
	[ -f ${OPM_STORE}/${_path} ] || opm_err "Non-existent entry"
	if [ ${_KEYRING} -gt 0 ]; then
		_pw=$(secret-tool lookup opm store || true)
		[ -z ${_pw} ] && echo "Enter password to store in the keychain" && \
			secret-tool store --label="OPM store" opm store && \
			_pw=$(secret-tool lookup opm store || true)
		if [ -z ${_pw} ]; then
			unset _KEYRING
		else
			make_temp && echo ${_pw} > ${_TMP}
		fi
	fi
	signify -Vq -p ${_SPUBLIC_KEY} -m ${OPM_STORE}/${_path} && \
	_e=$(openssl smime -decrypt -in ${OPM_STORE}/${_path} -inform PEM \
		-inkey ${_PRIVATE_KEY} ${_pw:+-passin file:${_TMP}})
	if [ ${_CLIP} -eq 0 ]; then
		[ -z ${_HIGHLIGHT} ] || tput smso && echo "${_e}" && \
			tput rmso || echo "${_e}"
	else
		[[ ${_e} == *\n* ]] && _ML=1
		opm_debug "Copying to clipboard=${_CBOARD}, multiline=${_ML}"
		[ ${_ML} -gt 0 ] && _e=$(echo "${_e}" | sed -n '2p')
		printf '%s' "${_e}" | xclip -selection ${_CBOARD} -loop 1
	fi
}

check_add_keys()
{
	[ -f ${_PUBLIC_KEY} ] || opm_err "missing ${_PUBLIC_KEY}"
	[ -f ${_SPRIVATE_KEY} ] || opm_err "missing ${_SPRIVATE_KEY}"
}

check_get_keys()
{
	[ -f ${_PRIVATE_KEY} ] || opm_err "missing ${_PRIVATE_KEY}"
	[ -f ${_SPUBLIC_KEY} ] || opm_err "missing ${_SPUBLIC_KEY}"
}

trap 'trap_handler' EXIT HUP INT TERM

while getopts C:S:P:bcdhkmp:s: arg; do
	case ${arg} in
		C) _CBOARD="${OPTARG}" ;;
		c) _CLIP=1 ;;
		S) _SPRIVATE_KEY="${OPTARG}" ;;
		s) _PRIVATE_KEY="${OPTARG}" ;;
		P) _SPUBLIC_KEY="${OPTARG}" ;;
		p) _PUBLIC_KEY="${OPTARG}" ;;
		d) _DEBUG=1 ;;
		m) _ML=1 ;;
		b) _BATCH=1 ;;
		h) _HIGHLIGHT=1 ;;
		k) command -v secret-tool >/dev/null && _KEYRING=1 ;;
		*) usage ;;
	esac
done
shift $((OPTIND - 1))

_PRIVATE_KEY=${_PRIVATE_KEY:-${OPM_KEYSTORE}/${USER}.key}
_PUBLIC_KEY=${_PUBLIC_KEY:-${OPM_KEYSTORE}/${USER}.pub}
_SPRIVATE_KEY=${_SPRIVATE_KEY:-${OPM_KEYSTORE}/signify.sec}
_SPUBLIC_KEY=${_SPUBLIC_KEY:-${OPM_KEYSTORE}/signify.pub}

opm_debug "Private key: ${_PRIVATE_KEY}"
opm_debug "Public key: ${_PUBLIC_KEY}"
opm_debug "Signify secret key: ${_SPRIVATE_KEY}"
opm_debug "Signify public key: ${_SPUBLIC_KEY}"

case ${1} in
add|insert)
	check_add_keys
	make_temp
	add_entry ${2}
	;;
del|rm)
	path_check ${2}
	del_entry ${2}
	;;
list|ls)
	show_list
	;;
encrypt)
	check_add_keys
	path_check ${2}
	make_temp
	encrypt ${2}
	;;
show|get)
	check_get_keys
	path_check ${2}
	show_entry ${2}
	;;
verify)
	check_get_keys
	verify
	;;
find|search)
	search ${2}
	;;
*)
	usage
	;;
esac
