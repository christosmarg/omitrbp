# $FreeBSD$

PROG=		omitrbp
SRCS=		${PROG}.c
MAN=		${PROG}.1
LDFLAGS+=	-lelf

.include <bsd.prog.mk>
