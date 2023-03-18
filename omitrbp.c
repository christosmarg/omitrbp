#include <sys/param.h>
#include <sys/sysctl.h>

#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct section {
	GElf_Shdr	sh;
	Elf_Scn		*scn;
	const char	*name;
};

static struct section *sl;
static size_t shnum;
static int first_instr = 0;

static void
print_rbp_ommited(const char *func, uint64_t lo, uint64_t hi)
{
	Elf_Data *d;
	struct section *s;
	uint8_t *buf;
	uint64_t addr;
	int i;

	for (i = 1; i < shnum; i++) {
		s = &sl[i];
		if (strcmp(s->name, ".text") != 0 ||
		    s->sh.sh_type != SHT_PROGBITS)
			continue;
		(void)elf_errno();
		if ((d = elf_getdata(s->scn, NULL)) == NULL) {
			if (elf_errno() != 0)
				warnx("elf_getdata(): %s", elf_errmsg(-1));
			continue;
		}
		if (d->d_size <= 0 || d->d_buf == NULL)
			continue;
		buf = d->d_buf;
		addr = s->sh.sh_addr + d->d_off;
		while (addr != lo) {
			addr++;
			buf++;
		}
		if (first_instr) {
			if (*buf != 0x55)
				puts(func);
		} else {
			int found = 0;

			while (addr != hi) {
				if (*buf == 0x55)
					found = 1;
				addr++;
				buf++;
			}
			if (!found)
				puts(func);
		}
		return;
	}
}

int
main(int argc, char *argv[])
{
	Elf *elf;
	Elf_Scn *scn;
	Elf_Data *d;
	GElf_Shdr sh;
	GElf_Sym sym;
	struct section *s;
	uint64_t lo, hi;
	uint32_t stab;
	const char *name, *func;
	char bootfile[BUFSIZ];
	size_t shstrndx, ndx, slen;
	int fd, len, i, j, ch;

	while ((ch = getopt(argc, argv, "f")) != -1) {
		switch (ch) {
		case 'f':
			first_instr = 1;
			break;
		case '?':
		default:
			fprintf(stderr, "usage: %s [-f]\n", argv[0]);
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	slen = sizeof(bootfile);
	if (sysctlbyname("kern.bootfile", bootfile, &slen, NULL, 0) != 0)
		strlcpy(bootfile, "/boot/kernel/kernel", sizeof(bootfile));

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(1, "elf_version(): %s", elf_errmsg(-1));
	if ((fd = open(bootfile, O_RDONLY)) < 0)
		err(1, "open(%s)", bootfile);
	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
		errx(1, "elf_begin(): %s", elf_errmsg(-1));
	if (elf_kind(elf) == ELF_K_NONE)
		errx(1, "not an ELF file: %s", bootfile);

	if (!elf_getshnum(elf, &shnum))
		errx(1, "elf_getshnum(): %s", elf_errmsg(-1));
	if ((sl = malloc(shnum * sizeof(struct section))) == NULL)
		err(1, "malloc");
	if (!elf_getshstrndx(elf, &shstrndx))
		errx(1, "elf_getshstrndx(): %s", elf_errmsg(-1));
	if ((scn = elf_getscn(elf, 0)) == NULL)
		errx(1, "elf_getscn(): %s", elf_errmsg(-1));
	(void)elf_errno();

	do {
		if (gelf_getshdr(scn, &sh) == NULL) {
			warnx("gelf_getshdr(): %s", elf_errmsg(-1));
			(void)elf_errno();
			continue;
		}
		if ((name = elf_strptr(elf, shstrndx, sh.sh_name)) == NULL)
			(void)elf_errno();
		if ((ndx = elf_ndxscn(scn)) == SHN_UNDEF && elf_errno() != 0) {
			warnx("elf_ndxscn(): %s", elf_errmsg(-1));
			continue;
		}
		if (ndx >= shnum)
			continue;
		s = &sl[ndx];
		s->scn = scn;
		s->sh = sh;
		s->name = name;
	} while ((scn = elf_nextscn(elf, scn)) != NULL);
	if (elf_errno() != 0)
		warnx("elf_nextscn(): %s", elf_errmsg(-1));

	for (i = 1; i < shnum; i++) {
		s = &sl[i];
		if (s->sh.sh_type != SHT_SYMTAB && s->sh.sh_type != SHT_DYNSYM)
			continue;
		if (s->sh.sh_link >= shnum)
			continue;
		stab = s->sh.sh_link;
		len = (int)(s->sh.sh_size / s->sh.sh_entsize);
		(void)elf_errno();
		if ((d = elf_getdata(s->scn, NULL)) == NULL) {
			if (elf_errno() != 0)
				warnx("elf_getdata(): %s", elf_errmsg(-1));
			continue;
		}
		if (d->d_size <= 0)
			continue;
		if (s->sh.sh_entsize == 0)
			continue;
		else if (len > INT_MAX)
			continue;
		for (j = 0; j < len; j++) {
			if (gelf_getsym(d, j, &sym) != &sym) {
				warnx("gelf_getsym(): %s", elf_errmsg(-1));
				continue;
			}
			if (GELF_ST_TYPE(sym.st_info) != STT_FUNC)
				continue;
			lo = sym.st_value;
			hi = sym.st_value + sym.st_size;
			if ((func = elf_strptr(elf, stab, sym.st_name)) != NULL)
				print_rbp_ommited(func, lo, hi);
		}
	}

	free(sl);
	close(fd);
	elf_end(elf);

	return (0);
}
