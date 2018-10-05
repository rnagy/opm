PREFIX=	/usr/local
BINDIR=	$(PREFIX)/bin
MANDIR=	$(PREFIX)/man/man

MAN=	opm.1

SCRIPT=	opm.sh

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${.CURDIR}/${SCRIPT} ${DESTDIR}${BINDIR}/opm

.include <bsd.prog.mk>
