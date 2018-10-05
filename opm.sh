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

OPM_STORE=${OPM_STORE:-${HOME}/.opm}
_CBOARD=primary
_CLIP=0
_DEBUG=0
_MULTILINE=0

[ -d ${OPM_STORE} ] || mkdir -p ${OPM_STORE}

_TMP=$(mktemp -p ${OPM_STORE} .XXXXXXXXXX)

trap_handler()
{
	set +e # we're trapped
	rm -f "${_TMP}"
}

opm_debug()
{
	[ ${_DEBUG} -gt 0 ] && echo "===> ${1}" || true
}

opm_err()
{
	echo "${1}" 1>&2 && return ${2:-1}
}

usage()
{
	opm_err "usage: ${0##*/} [-cdm] [-C clipboard] [-p file] [-s file] command"
}

find_sig()
{
	find ${OPM_STORE} -name '*.sig' -print 2>/dev/null
}

verify()
{
	local _e _f
	for _e in $(find_sig); do
		_e=${_e%%.sig}
		_f=$(echo ${_e} | sed "s,${OPM_STORE}/,,g")
		opm_debug "Verifying ${_f} with ${_SPUBLIC_KEY}"
		signify -Vq -p ${_SPUBLIC_KEY} -m ${_e} || opm_err "unable to verify ${_f}"
	done
}

encrypt()
{
	local _path=$1
	local _e _f
	if [ -z ${_path} ]; then
		for _e in $(find_sig); do
			_e=${_e%%.sig}
			_f=$(echo ${_e} | sed "s,${OPM_STORE}/,,g")
			encrypt ${_f} ${OPM_STORE}/${_f}
		done
	else
		[ -f ${OPM_STORE}/${_path} ] || opm_err "Non-existent entry" 
		do_encrypt ${_path} ${OPM_STORE}/${_path}
	fi
}

tree()
{
	awk '!/\.$/ {for (i=1;i<NF-1;i++){printf("|   ")}print "|-- "$NF}'  FS='/'
}

show_list()
{
	for _f in $(cd ${OPM_STORE} && find . -name '*.sig' 2>/dev/null); do
		_d=$(dirname $_f})
		until [[ ${_d} == '.' ]]; do
			_p="${_d} ${_p}"
			_d=$(dirname ${_d})
		done
		for _pe in ${_p}; do
			[[ " ${_pd[*]} " == *" $_pe "* ]] || \
				echo ${_pe} | tree && \
					_pd="${_pd} ${_pe}"
		done
		echo ${_f} | sed "s,.sig$,,g" | tree
	done
}

do_encrypt()
{
	local _path=$1
	local _encrypt=$2
	local _parent="${_path%/*}"
	local _recipients=${_PUBLIC_KEY}
	[ -d ${OPM_STORE}/${_parent}/.team ] && \
		_recipients="${_PUBLIC_KEY} $(ls ${OPM_STORE}/${_parent}/.team/*.pub)"

	for _k in ${_recipients}; do
		_cn=$(openssl x509 -noout -subject -in ${_k} | sed -n '/^subject/s/^.*CN=//p')
		opm_debug "Encrypting ${OPM_STORE}/${_path} for ${_cn}"
	done
	openssl smime -encrypt -aes256 -in ${_encrypt:=${_TMP}} -out ${OPM_STORE}/${_path} \
		-outform PEM ${_recipients}
	echo "Signing ${OPM_STORE}/${_path} with ${_SPRIVATE_KEY}"
	signify -S -s ${_SPRIVATE_KEY} -m ${OPM_STORE}/${_path}
}

add_entry()
{
	local _path=$1
	local _parent="${_path%/*}"
	[ -z ${_path} ] && opm_err "Empty path" 
	[ -d "${OPM_STORE}/${_parent}" ] || mkdir -p "${OPM_STORE}/${_parent}"

	if [ ${_MULTILINE} -gt 0 ]; then
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

del_entry()
{
	local _path=$1
	[ -f ${OPM_STORE}/${_path} ] || opm_err "Non-existent entry" 
	rm -i ${OPM_STORE}/${_path}
}

show_entry()
{
	local _e
	local _path=$1
	local _parent="${_path%/*}"
	[ -z ${_path} ] && opm_err "Empty path" 
	[ -f ${OPM_STORE}/${_path} ] || opm_err "Non-existent entry" 
	signify -V -p ${_SPUBLIC_KEY} -m ${OPM_STORE}/${_path} && \
	_e=$(openssl smime -decrypt -in ${OPM_STORE}/${_path} -inform PEM \
		-inkey ${_PRIVATE_KEY})
	if [ ${_CLIP} -eq 0 ]; then
		echo "${_e}"
	else
		opm_debug "Copying to clipboard=${_CBOARD}, multiline=${_MULTILINE}"
		[ ${_MULTILINE} -eq 0 ] && _e=$(echo "${_e}" | head -1)
		printf '%s' "${_e}" | xclip -selection ${_CBOARD} -loop 1
	fi
}

trap 'trap_handler' EXIT HUP INT TERM

while getopts C:cdmp:s: arg; do
	case ${arg} in
		C) _CBOARD="${OPTARG}" ;;
		c) _CLIP=1 ;;
		s) _PRIVATE_KEY="${OPTARG}" ;;
		p) _PUBLIC_KEY="${OPTARG}" ;;
		d) _DEBUG=1 ;;
		m) _MULTILINE=1 ;;
		*) usage ;;
	esac
done
shift $((OPTIND - 1))

_PRIVATE_KEY=${_PRIVATE_KEY:-${OPM_STORE}/${USER}.key}
_PUBLIC_KEY=${_PUBLIC_KEY:-${OPM_STORE}/${USER}.pub}
_SPRIVATE_KEY=${_SPRIVATE_KEY:-${OPM_STORE}/opm_signify.sec}
_SPUBLIC_KEY=${_SPUBLIC_KEY:-${OPM_STORE}/opm_signify.pub}

opm_debug "Private key: ${_PRIVATE_KEY}"
opm_debug "Public key: ${_PUBLIC_KEY}"
opm_debug "Signify secret key: ${_SPRIVATE_KEY}"
opm_debug "Signify public key: ${_SPUBLIC_KEY}"

case ${1} in
add|insert)
	add_entry ${2}
	;;
del|rm)
	del_entry ${2}
	;;
list|ls)
	show_list
	;;
encrypt)
	encrypt ${2}
	;;
show|get)
	show_entry ${2}
	;;
verify)
	verify
	;;
*)
	usage
	;;
esac
