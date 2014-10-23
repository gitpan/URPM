/* Copyright (c) 2002, 2003, 2004, 2005 MandrakeSoft SA
 * Copyright (c) 2005, 2006 Mandriva SA
 *
 * All rights reserved.
 * This program is free software; you can redistribute it and/or
 * modify it under the same terms as Perl itself.
 *
 * $Id: URPM.xs,v 1.109 2006/02/13 10:22:51 rgarciasuarez Exp $
 * 
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <sys/utsname.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <zlib.h>

#undef Fflush
#undef Mkdir
#undef Stat
#include <rpm/rpmlib.h>
#include <rpm/header.h>
#include <rpm/rpmio.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmts.h>
#include <rpm/rpmps.h>
#include <rpm/rpmpgp.h>
#include <rpm/rpmcli.h>
#include <rpm/rpmbuild.h>

struct s_Package {
  char *info;
  char *requires;
  char *obsoletes;
  char *conflicts;
  char *provides;
  char *rflags;
  char *summary;
  unsigned flag;
  Header h;
};

struct s_Transaction {
  rpmts ts;
  int count;
};

struct s_TransactionData {
  SV* callback_open;
  SV* callback_close;
  SV* callback_trans;
  SV* callback_uninst;
  SV* callback_inst;
  long min_delta;
  SV *data; /* chain with another data user provided */
};

typedef struct s_Transaction* URPM__DB;
typedef struct s_Transaction* URPM__Transaction;
typedef struct s_Package* URPM__Package;

#define FLAG_ID               0x001fffffU
#define FLAG_RATE             0x00e00000U
#define FLAG_BASE             0x01000000U
#define FLAG_SKIP             0x02000000U
#define FLAG_DISABLE_OBSOLETE 0x04000000U
#define FLAG_INSTALLED        0x08000000U
#define FLAG_REQUESTED        0x10000000U
#define FLAG_REQUIRED         0x20000000U
#define FLAG_UPGRADE          0x40000000U
#define FLAG_NO_HEADER_FREE   0x80000000U

#define FLAG_ID_MAX           0x001ffffe
#define FLAG_ID_INVALID       0x001fffff

#define FLAG_RATE_POS         21
#define FLAG_RATE_MAX         5
#define FLAG_RATE_INVALID     0


#define FILENAME_TAG 1000000
#define FILESIZE_TAG 1000001

#define FILTER_MODE_ALL_FILES     0
#define FILTER_MODE_UPGRADE_FILES 1
#define FILTER_MODE_CONF_FILES    2

/* promote epoch sense should be :
     0 for compability with old packages
     1 for rpm 4.2 and better new approach. */
#define PROMOTE_EPOCH_SENSE       1

/* these are in rpmlib but not in rpmlib.h */
int readLead(FD_t fd, struct rpmlead *lead);
/* Importing rpm hidden functions,
     Does RedHat try to force using their fucking functions using char **
     as direct mapping of rpm command line options ? */

/* almost direct importation of rpmio_internal.h */

/** \ingroup rpmio
 * Values parsed from OpenPGP signature/pubkey packet(s).
 */
struct pgpDigParams_s {
/*@only@*/ /*@null@*/
    const char * userid;
/*@only@*/ /*@null@*/
    const byte * hash;
    const char * params[4];
    byte tag;

    byte version;		/*!< version number. */
    byte time[4];		/*!< time that the key was created. */
    byte pubkey_algo;		/*!< public key algorithm. */

    byte hash_algo;
    byte sigtype;
    byte hashlen;
    byte signhash16[2];
    byte signid[8];
    byte saved;
#define	PGPDIG_SAVED_TIME	(1 << 0)
#define	PGPDIG_SAVED_ID		(1 << 1)

};

/** \ingroup rpmio
 * Container for values parsed from an OpenPGP signature and public key.
 */
struct pgpDig_s {
    struct pgpDigParams_s signature;
    struct pgpDigParams_s pubkey;

    size_t nbytes;		/*!< No. bytes of plain text. */

/*@only@*/ /*@null@*/
    DIGEST_CTX sha1ctx;		/*!< (dsa) sha1 hash context. */
/*@only@*/ /*@null@*/
    DIGEST_CTX hdrsha1ctx;	/*!< (dsa) header sha1 hash context. */
/*@only@*/ /*@null@*/
    void * sha1;		/*!< (dsa) V3 signature hash. */
    size_t sha1len;		/*!< (dsa) V3 signature hash length. */

/*@only@*/ /*@null@*/
    DIGEST_CTX md5ctx;		/*!< (rsa) md5 hash context. */
#ifdef	NOTYET
/*@only@*/ /*@null@*/
    DIGEST_CTX hdrmd5ctx;	/*!< (rsa) header md5 hash context. */
#endif
/*@only@*/ /*@null@*/
    void * md5;			/*!< (rsa) V3 signature hash. */
    size_t md5len;		/*!< (rsa) V3 signature hash length. */

    /* WARNING INCOMPLETE TYPE */
};

/** \ingroup rpmio
 */
typedef struct _FDSTACK_s {
    FDIO_t		io;
/*@dependent@*/ void *	fp;
    int			fdno;
} FDSTACK_t;

/** \ingroup rpmio
 * Cumulative statistics for an I/O operation.
 */
typedef struct {
    int			count;	/*!< Number of operations. */
    off_t		bytes;	/*!< Number of bytes transferred. */
    time_t		msecs;	/*!< Number of milli-seconds. */
} OPSTAT_t;

/** \ingroup rpmio
 * Identify per-desciptor I/O operation statistics.
 */
enum FDSTAT_e {
    FDSTAT_READ		= 0,	/*!< Read statistics index. */
    FDSTAT_WRITE	= 1,	/*!< Write statistics index. */
    FDSTAT_SEEK		= 2,	/*!< Seek statistics index. */
    FDSTAT_CLOSE	= 3	/*!< Close statistics index */
};

/** \ingroup rpmio
 * Cumulative statistics for a descriptor.
 */
typedef	/*@abstract@*/ struct {
    struct timeval	create;	/*!< Structure creation time. */
    struct timeval	begin;	/*!< Operation start time. */
    OPSTAT_t		ops[4];	/*!< Cumulative statistics. */
} * FDSTAT_t;

/** \ingroup rpmio
 */
typedef struct _FDDIGEST_s {
    pgpHashAlgo		hashalgo;
    DIGEST_CTX		hashctx;
} * FDDIGEST_t;

/** \ingroup rpmio
 * The FD_t File Handle data structure.
 */
struct _FD_s {
/*@refs@*/ int	nrefs;
    int		flags;
#define	RPMIO_DEBUG_IO		0x40000000
#define	RPMIO_DEBUG_REFS	0x20000000
    int		magic;
#define	FDMAGIC			0x04463138
    int		nfps;
    FDSTACK_t	fps[8];
    int		urlType;	/* ufdio: */

/*@dependent@*/ void *	url;	/* ufdio: URL info */
    int		rd_timeoutsecs;	/* ufdRead: per FD_t timer */
    ssize_t	bytesRemain;	/* ufdio: */
    ssize_t	contentLength;	/* ufdio: */
    int		persist;	/* ufdio: */
    int		wr_chunked;	/* ufdio: */

    int		syserrno;	/* last system errno encountered */
/*@observer@*/ const void *errcookie;	/* gzdio/bzdio/ufdio: */

    FDSTAT_t	stats;		/* I/O statistics */

    int		ndigests;
#define	FDDIGEST_MAX	4
    struct _FDDIGEST_s	digests[FDDIGEST_MAX];

    int		ftpFileDoneNeeded; /* ufdio: (FTP) */
    unsigned int firstFree;	/* fadio: */
    long int	fileSize;	/* fadio: */
    long int	fd_cpioPos;	/* cpio: */
};
/*@access FD_t@*/

static int rpmError_callback_data;
void rpmError_callback() {
  if (rpmErrorCode() != RPMERR_UNLINK && rpmErrorCode() != RPMERR_RMDIR) {
    write(rpmError_callback_data, rpmErrorString(), strlen(rpmErrorString()));
  }
}

static inline
void fdInitDigest(FD_t fd, pgpHashAlgo hashalgo, int flags)
	/*@modifies fd @*/
{
    FDDIGEST_t fddig = fd->digests + fd->ndigests;
    if (fddig != (fd->digests + FDDIGEST_MAX)) {
	fd->ndigests++;
	fddig->hashalgo = hashalgo;
	fddig->hashctx = rpmDigestInit(hashalgo, flags);
    }
}

/* end of incoporated rpmio_internal.h */

int rpmReadSignature(FD_t fd, Header *header, short sig_type, const char **msg);

/* needed for importing keys (from rpmio) */
int rpmioSlurp(const char * fn, const byte ** bp, ssize_t * blenp);
int b64decode (const char * s, void ** datap, size_t *lenp);

static void
get_fullname_parts(URPM__Package pkg, char **name, char **version, char **release, char **arch, char **eos) {
  char *_version = NULL, *_release = NULL, *_arch = NULL, *_eos = NULL;

  if ((_eos = strchr(pkg->info, '@')) != NULL) {
    *_eos = 0; /* mark end of string to enable searching backwards */
    if ((_arch = strrchr(pkg->info, '.')) != NULL) {
      *_arch = 0;
      if ((release != NULL || version != NULL || name != NULL) && (_release = strrchr(pkg->info, '-')) != NULL) {
	*_release = 0;
	if ((version != NULL || name != NULL) && (_version = strrchr(pkg->info, '-')) != NULL) {
	  if (name != NULL) *name = pkg->info;
	  if (version != NULL) *version = _version + 1;
	}
	if (release != NULL) *release = _release + 1;
	*_release = '-';
      }
      if (arch != NULL) *arch = _arch + 1;
      *_arch = '.';
    }
    if (eos != NULL) *eos = _eos;
    *_eos = '@';
  }
}

static char *
get_name(Header header, int_32 tag) {
  int_32 type, count;
  char *name;

  headerGetEntry(header, tag, &type, (void **) &name, &count);
  return name ? name : "";
}

static int
get_int(Header header, int_32 tag) {
  int_32 type, count;
  int *i;

  headerGetEntry(header, tag, &type, (void **) &i, &count);
  return i ? *i : 0;
}

static int
print_list_entry(char *buff, int sz, char *name, int_32 flags, char *evr) {
  int len = strlen(name);
  char *p = buff;

  if (len >= sz || !strncmp(name, "rpmlib(", 7)) return -1;
  memcpy(p, name, len); p += len;

  if (flags & (RPMSENSE_PREREQ|RPMSENSE_SCRIPT_PREUN|RPMSENSE_SCRIPT_PRE|RPMSENSE_SCRIPT_POSTUN|RPMSENSE_SCRIPT_POST)) {
    if (p - buff + 3 >= sz) return -1;
    memcpy(p, "[*]", 4); p += 3;
  }
  if (evr != NULL) {
    len = strlen(evr);
    if (len > 0) {
      if (p - buff + 6 + len >= sz) return -1;
      *p++ = '[';
      if (flags & RPMSENSE_LESS) *p++ = '<';
      if (flags & RPMSENSE_GREATER) *p++ = '>';
      if (flags & RPMSENSE_EQUAL) *p++ = '=';
      if ((flags & (RPMSENSE_LESS|RPMSENSE_EQUAL|RPMSENSE_GREATER)) == RPMSENSE_EQUAL) *p++ = '=';
      *p++ = ' ';
      memcpy(p, evr, len); p+= len;
      *p++ = ']';
    }
  }
  *p = 0; /* make sure to mark null char, Is it really necessary ? */

  return p - buff;
}

static int
ranges_overlap(int_32 aflags, char *sa, int_32 bflags, char *sb, int b_nopromote) {
  if (!aflags || !bflags)
    return 1; /* really faster to test it there instead of later */
  else {
    int sense = 0;
    char *eosa = strchr(sa, ']');
    char *eosb = strchr(sb, ']');
    char *ea, *va, *ra, *eb, *vb, *rb;

    if (eosa) *eosa = 0;
    if (eosb) *eosb = 0;
    /* parse sa as an [epoch:]version[-release] */
    for (ea = sa; *sa >= '0' && *sa <= '9'; ++sa);
    if (*sa == ':') {
      *sa++ = 0; /* ea could be an empty string (should be interpreted as 0) */
      va = sa;
    } else {
      va = ea; /* no epoch */
      ea = NULL;
    }
    if ((ra = strrchr(sa, '-'))) *ra++ = 0;
    /* parse sb as an [epoch:]version[-release] */
    for (eb = sb; *sb >= '0' && *sb <= '9'; ++sb);
    if (*sb == ':') {
      *sb++ = 0; /* ea could be an empty string (should be interpreted as 0) */
      vb = sb;
    } else {
      vb = eb; /* no epoch */
      eb = NULL;
    }
    if ((rb = strrchr(sb, '-'))) *rb++ = 0;
    /* now compare epoch */
    if (ea && eb)
      sense = rpmvercmp(*ea ? ea : "0", *eb ? eb : "0");
    else if (ea && *ea && atol(ea) > 0)
      sense = b_nopromote ? 1 : 0;
    else if (eb && *eb && atol(eb) > 0)
      sense = -1;
    /* now compare version and release if epoch has not been enough */
    if (sense == 0) {
      sense = rpmvercmp(va, vb);
      if (sense == 0 && ra && *ra && rb && *rb)
	sense = rpmvercmp(ra, rb);
    }
    /* restore all character that have been modified inline */
    if (rb) rb[-1] = '-';
    if (ra) ra[-1] = '-';
    if (eb) vb[-1] = ':';
    if (ea) va[-1] = ':';
    if (eosb) *eosb = ']';
    if (eosa) *eosa = ']';
    /* finish the overlap computation */
    if (sense < 0 && ((aflags & RPMSENSE_GREATER) || (bflags & RPMSENSE_LESS)))
      return 1;
    else if (sense > 0 && ((aflags & RPMSENSE_LESS) || (bflags & RPMSENSE_GREATER)))
      return 1;
    else if (sense == 0 && (((aflags & RPMSENSE_EQUAL) && (bflags & RPMSENSE_EQUAL)) ||
			    ((aflags & RPMSENSE_LESS) && (bflags & RPMSENSE_LESS)) ||
			    ((aflags & RPMSENSE_GREATER) && (bflags & RPMSENSE_GREATER))))
      return 1;
    else
      return 0;
  }
}

typedef int (*callback_list_str)(char *s, int slen, char *name, int_32 flags, char *evr, void *param);

static int
callback_list_str_xpush(char *s, int slen, char *name, int_32 flags, char *evr, void *param) {
  dSP;
  if (s) {
    XPUSHs(sv_2mortal(newSVpv(s, slen)));
  } else {
    char buff[4096];
    int len = print_list_entry(buff, sizeof(buff)-1, name, flags, evr);
    if (len >= 0)
      XPUSHs(sv_2mortal(newSVpv(buff, len)));
  }
  PUTBACK;
  /* returning zero indicates to continue processing */
  return 0;
}

struct cb_overlap_s {
  char *name;
  int_32 flags;
  char *evr;
  int direction; /* indicate to compare the above at left or right to the iteration element */
  int b_nopromote;
};

static int
callback_list_str_overlap(char *s, int slen, char *name, int_32 flags, char *evr, void *param) {
  struct cb_overlap_s *os = (struct cb_overlap_s *)param;
  int result = 0;
  char *eos = NULL;
  char *eon = NULL;
  char eosc = '\0';
  char eonc = '\0';

  /* we need to extract name, flags and evr from a full sense information, store result in local copy */
  if (s) {
    if (slen) { eos = s + slen; eosc = *eos; *eos = 0; }
    name = s;
    while (*s && *s != ' ' && *s != '[' && *s != '<' && *s != '>' && *s != '=') ++s;
    if (*s) {
      eon = s;
      while (*s) {
	if (*s == ' ' || *s == '[' || *s == '*' || *s == ']');
	else if (*s == '<') flags |= RPMSENSE_LESS;
	else if (*s == '>') flags |= RPMSENSE_GREATER;
	else if (*s == '=') flags |= RPMSENSE_EQUAL;
	else break;
	++s;
      }
      evr = s;
    } else
      evr = "";
  }

  /* mark end of name */
  if (eon) { eonc = *eon; *eon = 0; }
  /* names should be equal, else it will not overlap */
  if (!strcmp(name, os->name)) {
    /* perform overlap according to direction needed, negative for left */
    if (os->direction < 0)
      result = ranges_overlap(os->flags, os->evr, flags, evr, os->b_nopromote);
    else
      result = ranges_overlap(flags, evr, os->flags, os->evr, os->b_nopromote);
  }

  /* fprintf(stderr, "cb_list_str_overlap result=%d, os->direction=%d, os->name=%s, os->evr=%s, name=%s, evr=%s\n",
     result, os->direction, os->name, os->evr, name, evr); */

  /* restore s if needed */
  if (eon) *eon = eonc;
  if (eos) *eos = eosc;

  return result;
}

static int
return_list_str(char *s, Header header, int_32 tag_name, int_32 tag_flags, int_32 tag_version, callback_list_str f, void *param) {
  int count = 0;

  if (s != NULL) {
    char *ps = strchr(s, '@');
    if (tag_flags && tag_version) {
      while(ps != NULL) {
	++count;
	if (f(s, ps-s, NULL, 0, NULL, param)) return -count;
	s = ps + 1; ps = strchr(s, '@');
      }
      ++count;
      if (f(s, 0, NULL, 0, NULL, param)) return -count;
    } else {
      char *eos;
      while(ps != NULL) {
	*ps = 0; eos = strchr(s, '['); if (!eos) eos = strchr(s, ' ');
	++count;
	if (f(s, eos ? eos-s : ps-s, NULL, 0, NULL, param)) { *ps = '@'; return -count; }
	*ps = '@'; /* restore in memory modified char */
	s = ps + 1; ps = strchr(s, '@');
      }
      eos = strchr(s, '['); if (!eos) eos = strchr(s, ' ');
      ++count;
      if (f(s, eos ? eos-s : 0, NULL, 0, NULL, param)) return -count;
    }
  } else if (header) {
    int_32 type, c;
    char **list = NULL;
    int_32 *flags = NULL;
    char **list_evr = NULL;
    int i;

    headerGetEntry(header, tag_name, &type, (void **) &list, &c);
    if (list) {
      if (tag_flags) headerGetEntry(header, tag_flags, &type, (void **) &flags, &c);
      if (tag_version) headerGetEntry(header, tag_version, &type, (void **) &list_evr, &c);
      for(i = 0; i < c; i++) {
	++count;
	if (f(NULL, 0, list[i], flags ? flags[i] : 0, list_evr ? list_evr[i] : NULL, param)) {
	  free(list);
	  free(list_evr);
	  return -count;
	}
      }
      free(list);
      free(list_evr);
    }
  }
  return count;
}

void
return_list_int_32(Header header, int_32 tag_name) {
  dSP;
  if (header) {
    int_32 type, count;
    int_32 *list = NULL;
    int i;

    headerGetEntry(header, tag_name, &type, (void **) &list, &count);
    if (list) {
      for(i = 0; i < count; i++) {
	XPUSHs(sv_2mortal(newSViv(list[i])));
      }
    }
  }
  PUTBACK;
}

void
return_list_uint_16(Header header, int_32 tag_name) {
  dSP;
  if (header) {
    int_32 type, count;
    uint_16 *list = NULL;
    int i;

    headerGetEntry(header, tag_name, &type, (void **) &list, &count);
    if (list) {
      for(i = 0; i < count; i++) {
	XPUSHs(sv_2mortal(newSViv(list[i])));
      }
    }
  }
  PUTBACK;
}

void
return_list_tag_modifier(Header header, int_32 tag_name) {
  dSP;
  int i;
  int_32 *list;
  int_32 count, type;
  headerGetEntry(header, tag_name, &type, (void **) &list, &count);

  for (i = 0; i < count; i++) {
    char buff[15];
    char *s = buff;
    switch (tag_name) {
    case RPMTAG_FILEFLAGS:
      if (list[i] & RPMFILE_CONFIG)    *s++ = 'c';
      if (list[i] & RPMFILE_DOC)       *s++ = 'd';
      if (list[i] & RPMFILE_GHOST)     *s++ = 'g';
      if (list[i] & RPMFILE_LICENSE)   *s++ = 'l';
      if (list[i] & RPMFILE_MISSINGOK) *s++ = 'm';
      if (list[i] & RPMFILE_NOREPLACE) *s++ = 'n';
      if (list[i] & RPMFILE_SPECFILE)  *s++ = 'S';
      if (list[i] & RPMFILE_README)    *s++ = 'R';
      if (list[i] & RPMFILE_EXCLUDE)   *s++ = 'e';
      if (list[i] & RPMFILE_ICON)      *s++ = 'i';
      if (list[i] & RPMFILE_UNPATCHED) *s++ = 'u';
      if (list[i] & RPMFILE_PUBKEY)    *s++ = 'p';
    break;
    default:
      return;  
    }
    *s = '\0';
    XPUSHs(sv_2mortal(newSVpv(buff, strlen(buff))));
  }
  PUTBACK;
}

void
return_list_tag(URPM__Package pkg, int_32 tag_name) {
  dSP;
  if (pkg->h != NULL) {
    void *list = NULL;
    int_32 count, type;
    headerGetEntry(pkg->h, tag_name, &type, (void **) &list, &count);

    if (list) {
      if (tag_name == RPMTAG_ARCH) {
	XPUSHs(sv_2mortal(newSVpv(headerIsEntry(pkg->h, RPMTAG_SOURCEPACKAGE) ? "src" : (char *) list, 0)));
      } else
	switch (type) {
	  case RPM_NULL_TYPE:
	    break;
	  case RPM_CHAR_TYPE:
	  case RPM_INT8_TYPE:
	  case RPM_INT16_TYPE:
	  case RPM_INT32_TYPE:
	    {
	      int i;
	      int *r;
	      r = (int *)list;
	      for (i=0; i < count; i++) {
		XPUSHs(sv_2mortal(newSViv(r[i])));
	      }
	    }
	    break;
	  case RPM_STRING_TYPE:
	    XPUSHs(sv_2mortal(newSVpv((char *) list, 0)));
	    break;
	  case RPM_BIN_TYPE:
	    break;
	  case RPM_STRING_ARRAY_TYPE:
	    {
	      int i;
	      char **s;

	      s = (char **)list;
	      for (i = 0; i < count; i++) {
		XPUSHs(sv_2mortal(newSVpv(s[i], 0)));
	      }
	    }
	    break;
	  case RPM_I18NSTRING_TYPE:
	    break;
	}
    }
  } else {
    char *name;
    char *version;
    char *release;
    char *arch;
    char *eos;
    switch (tag_name) {
      case RPMTAG_NAME:
	{
	  get_fullname_parts(pkg, &name, &version, &release, &arch, &eos);
	  if (version - name < 1) croak("invalid fullname");
	  XPUSHs(sv_2mortal(newSVpv(name, version-name - 1)));
	}
	break;
      case RPMTAG_VERSION:
	{
	  get_fullname_parts(pkg, &name, &version, &release, &arch, &eos);
	  if (release - version < 1) croak("invalid fullname");
	  XPUSHs(sv_2mortal(newSVpv(version, release-version - 1)));
	}
	break;
      case RPMTAG_RELEASE:
	{
	  get_fullname_parts(pkg, &name, &version, &release, &arch, &eos);
	  if (arch - release < 1) croak("invalid fullname");
	  XPUSHs(sv_2mortal(newSVpv(release, arch-release - 1)));
	}
	break;
      case RPMTAG_ARCH:
	{
	  get_fullname_parts(pkg, &name, &version, &release, &arch, &eos);
	  XPUSHs(sv_2mortal(newSVpv(arch, eos-arch)));
	}
	break;
      case RPMTAG_SUMMARY:
	XPUSHs(sv_2mortal(newSVpv(pkg->summary, 0)));
	break;
    }
  }
  PUTBACK;
}


void
return_files(Header header, int filter_mode) {
  dSP;
  if (header) {
    char buff[4096];
    char *p, *s;
    STRLEN len;
    int_32 type, count;
    char **list = NULL;
    char **baseNames = NULL;
    char **dirNames = NULL;
    int_32 *dirIndexes = NULL;
    int_32 *flags = NULL;
    uint_16 *fmodes = NULL;
    int i;

    if (filter_mode) {
      headerGetEntry(header, RPMTAG_FILEFLAGS, &type, (void **) &flags, &count);
      headerGetEntry(header, RPMTAG_FILEMODES, &type, (void **) &fmodes, &count);
    }

    headerGetEntry(header, RPMTAG_BASENAMES, &type, (void **) &baseNames, &count);
    headerGetEntry(header, RPMTAG_DIRINDEXES, &type, (void **) &dirIndexes, NULL);
    headerGetEntry(header, RPMTAG_DIRNAMES, &type, (void **) &dirNames, NULL);
    if (!baseNames || !dirNames || !dirIndexes) {
      headerGetEntry(header, RPMTAG_OLDFILENAMES, &type, (void **) &list, &count);
      if (!list) return;
    }

    for(i = 0; i < count; i++) {
      if (list) {
	s = list[i];
	len = strlen(list[i]);
      } else {
	len = strlen(dirNames[dirIndexes[i]]);
	if (len >= sizeof(buff)) continue;
	memcpy(p = buff, dirNames[dirIndexes[i]], len + 1); p += len;
	len = strlen(baseNames[i]);
	if (p - buff + len >= sizeof(buff)) continue;
	memcpy(p, baseNames[i], len + 1); p += len;
	s = buff;
	len = p-buff;
      }

      if (filter_mode) {
	if ((filter_mode & FILTER_MODE_CONF_FILES) && flags && (flags[i] & RPMFILE_CONFIG) == 0) continue;
	if ((filter_mode & FILTER_MODE_UPGRADE_FILES) && fmodes &&
	    (S_ISDIR(fmodes[i]) || S_ISLNK(fmodes[i]) ||
	     !strncmp(s, "/dev", 4) || !strncmp(s, "/etc/rc.d", 9) ||
	     (len >= 3 && !strncmp(s+len-3, ".la", 3)))) continue;
      }

      XPUSHs(sv_2mortal(newSVpv(s, len)));
    }

    free(baseNames);
    free(dirNames);
    free(list);
  }
  PUTBACK;
}

void
return_problems(rpmps ps, int translate_message) {
  dSP;
  if (ps && ps->probs && ps->numProblems > 0) {
    int i;

    for (i = 0; i < ps->numProblems; i++) {
      rpmProblem p = ps->probs + i;

      if (p->ignoreProblem)
	continue;

      if (translate_message) {
	/* translate error using rpm localization */
	const char *buf = rpmProblemString(ps->probs + i);
	XPUSHs(sv_2mortal(newSVpv(buf, 0)));
	_free(buf);
      } else {
	const char *pkgNEVR = p->pkgNEVR ? p->pkgNEVR : "";
	const char *altNEVR = p->altNEVR ? p->altNEVR : "";
	const char *s = p->str1 ? p->str1 : "";
	SV *sv;

	switch (p->type) {
	case RPMPROB_BADARCH:
	  sv = newSVpvf("badarch@%s", pkgNEVR); break;

	case RPMPROB_BADOS:
	  sv = newSVpvf("bados@%s", pkgNEVR); break;

	case RPMPROB_PKG_INSTALLED:
	  sv = newSVpvf("installed@%s", pkgNEVR); break;

	case RPMPROB_BADRELOCATE:
	  sv = newSVpvf("badrelocate@%s@%s", pkgNEVR, s); break;

	case RPMPROB_NEW_FILE_CONFLICT:
	case RPMPROB_FILE_CONFLICT:
	  sv = newSVpvf("conflicts@%s@%s@%s", pkgNEVR, altNEVR, s); break;

	case RPMPROB_OLDPACKAGE:
	  sv = newSVpvf("installed@%s@%s", pkgNEVR, altNEVR); break;

	case RPMPROB_DISKSPACE:
	  sv = newSVpvf("diskspace@%s@%s@%ld", pkgNEVR, s, p->ulong1); break;

	case RPMPROB_DISKNODES:
	  sv = newSVpvf("disknodes@%s@%s@%ld", pkgNEVR, s, p->ulong1); break;

	case RPMPROB_BADPRETRANS:
	  sv = newSVpvf("badpretrans@%s@%s@%s", pkgNEVR, s, strerror(p->ulong1)); break;

	case RPMPROB_REQUIRES:
	  sv = newSVpvf("requires@%s@%s", pkgNEVR, altNEVR+2); break;

	case RPMPROB_CONFLICT:
	  sv = newSVpvf("conflicts@%s@%s", pkgNEVR, altNEVR+2); break;

	default:
	  sv = newSVpvf("unknown@%s", pkgNEVR); break;
	}
	XPUSHs(sv_2mortal(sv));
      }
    }
  }
  PUTBACK;
}

static char *
pack_list(Header header, int_32 tag_name, int_32 tag_flags, int_32 tag_version) {
  char buff[65536];
  int_32 type, count;
  char **list = NULL;
  int_32 *flags = NULL;
  char **list_evr = NULL;
  int i;
  char *p = buff;

  headerGetEntry(header, tag_name, &type, (void **) &list, &count);
  if (list) {
    if (tag_flags) headerGetEntry(header, tag_flags, &type, (void **) &flags, &count);
    if (tag_version) headerGetEntry(header, tag_version, &type, (void **) &list_evr, &count);
    for(i = 0; i < count; i++) {
      int len = print_list_entry(p, sizeof(buff)-(p-buff)-1, list[i], flags ? flags[i] : 0, list_evr ? list_evr[i] : NULL);
      if (len < 0) continue;
      p += len;
      *p++ = '@';
    }
    if (p > buff) p[-1] = 0;

    free(list);
    free(list_evr);
  }

  return p > buff ? memcpy(malloc(p-buff), buff, p-buff) : NULL;
}

static void
pack_header(URPM__Package pkg) {
  if (pkg->h) {
    if (pkg->info == NULL) {
      char buff[1024];
      char *p = buff;
      char *name = get_name(pkg->h, RPMTAG_NAME);
      char *version = get_name(pkg->h, RPMTAG_VERSION);
      char *release = get_name(pkg->h, RPMTAG_RELEASE);
      char *arch = headerIsEntry(pkg->h, RPMTAG_SOURCEPACKAGE) ? "src" : get_name(pkg->h, RPMTAG_ARCH);
      char *filename = get_name(pkg->h, FILENAME_TAG);

      p += snprintf(buff, sizeof(buff), "%s-%s-%s.%s@%d@%d@%s@", name, version, release, arch,
		    get_int(pkg->h, RPMTAG_EPOCH), get_int(pkg->h, RPMTAG_SIZE), get_name(pkg->h, RPMTAG_GROUP));
      if (filename) snprintf(p, sizeof(buff) - (p-buff), "%s-%s-%s.%s.rpm", name, version, release, arch);
      if (!filename || !strcmp(p, filename)) {
	p[-1] = 0;
      } else {
	p = p + 1 + snprintf(p, sizeof(buff) - (p-buff), "%s", filename);
      }
      pkg->info = memcpy(malloc(p-buff), buff, p-buff);
    }
    if (pkg->requires == NULL)
      pkg->requires = pack_list(pkg->h, RPMTAG_REQUIRENAME, RPMTAG_REQUIREFLAGS, RPMTAG_REQUIREVERSION);
    if (pkg->obsoletes == NULL)
      pkg->obsoletes = pack_list(pkg->h, RPMTAG_OBSOLETENAME, RPMTAG_OBSOLETEFLAGS, RPMTAG_OBSOLETEVERSION);
    if (pkg->conflicts == NULL)
      pkg->conflicts = pack_list(pkg->h, RPMTAG_CONFLICTNAME, RPMTAG_CONFLICTFLAGS, RPMTAG_CONFLICTVERSION);
    if (pkg->provides == NULL)
      pkg->provides = pack_list(pkg->h, RPMTAG_PROVIDENAME, RPMTAG_PROVIDEFLAGS, RPMTAG_PROVIDEVERSION);
    if (pkg->summary == NULL) {
      char *summary = get_name(pkg->h, RPMTAG_SUMMARY);
      int len = 1 + strlen(summary);

      pkg->summary = memcpy(malloc(len), summary, len);
    }

    if (!(pkg->flag & FLAG_NO_HEADER_FREE)) headerFree(pkg->h);
    pkg->h = 0;
  }
}

static void
update_provide_entry(char *name, STRLEN len, int force, IV use_sense, URPM__Package pkg, HV *provides) {
  SV** isv;

  if (!len) len = strlen(name);
  if ((isv = hv_fetch(provides, name, len, force))) {
    /* check if an entry has been found or created, it should so be updated */
    if (!SvROK(*isv) || SvTYPE(SvRV(*isv)) != SVt_PVHV) {
      SV* choice_set = (SV*)newHV();
      if (choice_set) {
	SvREFCNT_dec(*isv); /* drop the old as we are changing it */
	if (!(*isv = newRV_noinc(choice_set))) {
	  SvREFCNT_dec(choice_set);
	  *isv = &PL_sv_undef;
	}
      }
    }
    if (isv && *isv != &PL_sv_undef) {
      char id[8];
      STRLEN id_len = snprintf(id, sizeof(id), "%d", pkg->flag & FLAG_ID);
      SV **sense = hv_fetch((HV*)SvRV(*isv), id, id_len, 1);
      if (sense && use_sense) sv_setiv(*sense, use_sense);
    }
  }
}

static void
update_provides(URPM__Package pkg, HV *provides) {
  if (pkg->h) {
    int len;
    int_32 type, count;
    char **list = NULL;
    int_32 *flags = NULL;
    int i;

    /* examine requires for files which need to be marked in provides */
    headerGetEntry(pkg->h, RPMTAG_REQUIRENAME, &type, (void **) &list, &count);
    if (list) {
      for (i = 0; i < count; ++i) {
	len = strlen(list[i]);
	if (list[i][0] == '/') hv_fetch(provides, list[i], len, 1);
      }
    }

    /* update all provides */
    headerGetEntry(pkg->h, RPMTAG_PROVIDENAME, &type, (void **) &list, &count);
    if (list) {
      headerGetEntry(pkg->h, RPMTAG_PROVIDEFLAGS, &type, (void **) &flags, &count);
      for (i = 0; i < count; ++i) {
	len = strlen(list[i]);
	if (!strncmp(list[i], "rpmlib(", 7)) continue;
	update_provide_entry(list[i], len, 1, flags && flags[i] & (RPMSENSE_PREREQ|RPMSENSE_SCRIPT_PREUN|RPMSENSE_SCRIPT_PRE|RPMSENSE_SCRIPT_POSTUN|RPMSENSE_SCRIPT_POST|RPMSENSE_LESS|RPMSENSE_EQUAL|RPMSENSE_GREATER),
			     pkg, provides);
      }
    }
  } else {
    char *ps, *s, *es;

    if ((s = pkg->requires) != NULL && *s != 0) {
      ps = strchr(s, '@');
      while(ps != NULL) {
	if (s[0] == '/') {
	  *ps = 0; es = strchr(s, '['); if (!es) es = strchr(s, ' '); *ps = '@';
	  hv_fetch(provides, s, es != NULL ? es-s : ps-s, 1);
	}
	s = ps + 1; ps = strchr(s, '@');
      }
      if (s[0] == '/') {
	es = strchr(s, '['); if (!es) es = strchr(s, ' ');
	hv_fetch(provides, s, es != NULL ? es-s : strlen(s), 1);
      }
    }

    if ((s = pkg->provides) != NULL && *s != 0) {
      char *es;

      ps = strchr(s, '@');
      while(ps != NULL) {
	*ps = 0; es = strchr(s, '['); if (!es) es = strchr(s, ' '); *ps = '@';
	update_provide_entry(s, es != NULL ? es-s : ps-s, 1, es != NULL, pkg, provides);
	s = ps + 1; ps = strchr(s, '@');
      }
      es = strchr(s, '['); if (!es) es = strchr(s, ' ');
      update_provide_entry(s, es != NULL ? es-s : 0, 1, es != NULL, pkg, provides);
    }
  }
}

static void
update_provides_files(URPM__Package pkg, HV *provides) {
  if (pkg->h) {
    STRLEN len;
    int_32 type, count;
    char **list = NULL;
    char **baseNames = NULL;
    char **dirNames = NULL;
    int_32 *dirIndexes = NULL;
    int i;

    headerGetEntry(pkg->h, RPMTAG_BASENAMES, &type, (void **) &baseNames, &count);
    headerGetEntry(pkg->h, RPMTAG_DIRINDEXES, &type, (void **) &dirIndexes, NULL);
    headerGetEntry(pkg->h, RPMTAG_DIRNAMES, &type, (void **) &dirNames, NULL);
    if (baseNames && dirNames && dirIndexes) {
      char buff[4096];
      char *p;

      for(i = 0; i < count; i++) {
	len = strlen(dirNames[dirIndexes[i]]);
	if (len >= sizeof(buff)) continue;
	memcpy(p = buff, dirNames[dirIndexes[i]], len + 1); p += len;
	len = strlen(baseNames[i]);
	if (p - buff + len >= sizeof(buff)) continue;
	memcpy(p, baseNames[i], len + 1); p += len;

	update_provide_entry(buff, p-buff, 0, 0, pkg, provides);
      }

      free(baseNames);
      free(dirNames);
    } else {
      headerGetEntry(pkg->h, RPMTAG_OLDFILENAMES, &type, (void **) &list, &count);
      if (list) {
	for (i = 0; i < count; i++) {
	  len = strlen(list[i]);

	  update_provide_entry(list[i], len, 0, 0, pkg, provides);
	}

	free(list);
      }
    }
  }
}

int
open_archive(char *filename, pid_t *pid) {
  int fd;
  struct {
    char header[4];
    char toc_d_count[4];
    char toc_l_count[4];
    char toc_f_count[4];
    char toc_str_size[4];
    char uncompress[40];
    char trailer[4];
  } buf;

  fd = open(filename, O_RDONLY);
  if (fd >= 0) {
    lseek(fd, -(int)sizeof(buf), SEEK_END);
    if (read(fd, &buf, sizeof(buf)) != sizeof(buf) || strncmp(buf.header, "cz[0", 4) || strncmp(buf.trailer, "0]cz", 4)) {
      /* this is not an archive, open it without magic, but first rewind at begin of file */
      lseek(fd, 0, SEEK_SET);
    } else {
      /* this is an archive, create a pipe and fork for reading with uncompress defined inside */
      int fdno[2];

      if (!pipe(fdno)) {
	if ((*pid = fork()) != 0) {
	  fd_set readfds;
	  struct timeval timeout;

	  FD_ZERO(&readfds);
	  FD_SET(fdno[0], &readfds);
	  timeout.tv_sec = 1;
	  timeout.tv_usec = 0;
	  select(fdno[0]+1, &readfds, NULL, NULL, &timeout);

	  close(fd);
	  fd = fdno[0];
	  close(fdno[1]);
	} else {
	  char *unpacker[22]; /* enough for 40 bytes in uncompress to never overbuf */
	  char *p = buf.uncompress;
	  int ip = 0;
	  char *ld_loader = getenv("LD_LOADER");

	  if (ld_loader && *ld_loader) {
	    unpacker[ip++] = ld_loader;
	  }

	  buf.trailer[0] = 0; /* make sure end-of-string is right */
	  while (*p) {
	    if (*p == ' ' || *p == '\t') *p++ = 0;
	    else {
	      unpacker[ip++] = p;
	      while (*p && *p != ' ' && *p != '\t') ++p;
	    }
	  }
	  unpacker[ip] = NULL; /* needed for execlp */

	  lseek(fd, 0, SEEK_SET);
	  dup2(fd, STDIN_FILENO); close(fd);
	  dup2(fdno[1], STDOUT_FILENO); close(fdno[1]);
	  fd = open("/dev/null", O_WRONLY);
	  dup2(fd, STDERR_FILENO); close(fd);
	  execvp(unpacker[0], unpacker);
	  exit(1);
	}
      } else {
	close(fd);
	fd = -1;
      }
    }
  }
  return fd;
}

static int
call_package_callback(SV *urpm, SV *sv_pkg, SV *callback) {
  if (sv_pkg != NULL && callback != NULL) {
    int count;

    /* now, a callback will be called for sure */
    dSP;
    PUSHMARK(SP);
    XPUSHs(urpm);
    XPUSHs(sv_pkg);
    PUTBACK;
    count = call_sv(callback, G_SCALAR);
    SPAGAIN;
    if (count == 1 && !POPi) {
      /* package should not be added in depslist, so we free it */
      SvREFCNT_dec(sv_pkg);
      sv_pkg = NULL;
    }
    PUTBACK;
  }

  return sv_pkg != NULL;
}

static void
parse_line(AV *depslist, HV *provides, URPM__Package pkg, char *buff, SV *urpm, SV *callback) {
  SV *sv_pkg;
  URPM__Package _pkg;
  char *tag, *data;
  int data_len;

  if ((tag = strchr(buff, '@')) != NULL && (data = strchr(tag+1, '@')) != NULL) {
    *tag++ = *data++ = 0;
    data_len = 1+strlen(data);
    if (!strcmp(tag, "info")) {
      pkg->info = memcpy(malloc(data_len), data, data_len);
      pkg->flag &= ~FLAG_ID;
      pkg->flag |= 1 + av_len(depslist);
      sv_pkg = sv_setref_pv(newSVpv("", 0), "URPM::Package",
			    _pkg = memcpy(malloc(sizeof(struct s_Package)), pkg, sizeof(struct s_Package)));
      if (call_package_callback(urpm, sv_pkg, callback)) {
	if (provides) update_provides(_pkg, provides);
	av_push(depslist, sv_pkg);
      }
      memset(pkg, 0, sizeof(struct s_Package));
    } else if (!strcmp(tag, "requires")) {
      free(pkg->requires); pkg->requires = memcpy(malloc(data_len), data, data_len);
    } else if (!strcmp(tag, "obsoletes")) {
      free(pkg->obsoletes); pkg->obsoletes = memcpy(malloc(data_len), data, data_len);
    } else if (!strcmp(tag, "conflicts")) {
      free(pkg->conflicts); pkg->conflicts = memcpy(malloc(data_len), data, data_len);
    } else if (!strcmp(tag, "provides")) {
      free(pkg->provides); pkg->provides = memcpy(malloc(data_len), data, data_len);
    } else if (!strcmp(tag, "summary")) {
      free(pkg->summary); pkg->summary = memcpy(malloc(data_len), data, data_len);
    }
  }
}

static int
update_header(char *filename, URPM__Package pkg, int keep_all_tags, int vsflags) {
  int d = open(filename, O_RDONLY);

  if (d >= 0) {
    unsigned char sig[4];

    if (read(d, &sig, sizeof(sig)) == sizeof(sig)) {
      lseek(d, 0, SEEK_SET);
      if (sig[0] == 0xed && sig[1] == 0xab && sig[2] == 0xee && sig[3] == 0xdb) {
	FD_t fd = fdDup(d);
	Header header;
	rpmts ts;
	/* rpmVSFlags vsflags, ovsflags; */

	close(d);
	ts = rpmtsCreate();
	rpmtsSetVSFlags(ts, _RPMVSF_NOSIGNATURES | vsflags);
	if (fd != NULL && rpmReadPackageFile(ts, fd, filename, &header) == 0) {
	  struct stat sb;
	  char *basename;
	  int_32 size;

	  basename = strrchr(filename, '/');
	  fstat(fdFileno(fd), &sb);
	  fdClose(fd);
	  size = sb.st_size;
	  headerAddEntry(header, FILENAME_TAG, RPM_STRING_TYPE, basename != NULL ? basename + 1 : filename, 1);
	  headerAddEntry(header, FILESIZE_TAG, RPM_INT32_TYPE, &size, 1);

	  if (pkg->h && !(pkg->flag & FLAG_NO_HEADER_FREE)) headerFree(pkg->h);
	  pkg->h = header;
	  pkg->flag &= ~FLAG_NO_HEADER_FREE;

	  if (!keep_all_tags) {
	    headerRemoveEntry(pkg->h, RPMTAG_POSTIN);
	    headerRemoveEntry(pkg->h, RPMTAG_POSTUN);
	    headerRemoveEntry(pkg->h, RPMTAG_PREIN);
	    headerRemoveEntry(pkg->h, RPMTAG_PREUN);
	    headerRemoveEntry(pkg->h, RPMTAG_FILEUSERNAME);
	    headerRemoveEntry(pkg->h, RPMTAG_FILEGROUPNAME);
	    headerRemoveEntry(pkg->h, RPMTAG_FILEVERIFYFLAGS);
	    headerRemoveEntry(pkg->h, RPMTAG_FILERDEVS);
	    headerRemoveEntry(pkg->h, RPMTAG_FILEMTIMES);
	    headerRemoveEntry(pkg->h, RPMTAG_FILEDEVICES);
	    headerRemoveEntry(pkg->h, RPMTAG_FILEINODES);
	    headerRemoveEntry(pkg->h, RPMTAG_TRIGGERSCRIPTS);
	    headerRemoveEntry(pkg->h, RPMTAG_TRIGGERVERSION);
	    headerRemoveEntry(pkg->h, RPMTAG_TRIGGERFLAGS);
	    headerRemoveEntry(pkg->h, RPMTAG_TRIGGERNAME);
	    headerRemoveEntry(pkg->h, RPMTAG_CHANGELOGTIME);
	    headerRemoveEntry(pkg->h, RPMTAG_CHANGELOGNAME);
	    headerRemoveEntry(pkg->h, RPMTAG_CHANGELOGTEXT);
	    headerRemoveEntry(pkg->h, RPMTAG_ICON);
	    headerRemoveEntry(pkg->h, RPMTAG_GIF);
	    headerRemoveEntry(pkg->h, RPMTAG_VENDOR);
	    headerRemoveEntry(pkg->h, RPMTAG_EXCLUDE);
	    headerRemoveEntry(pkg->h, RPMTAG_EXCLUSIVE);
	    headerRemoveEntry(pkg->h, RPMTAG_DISTRIBUTION);
	    headerRemoveEntry(pkg->h, RPMTAG_VERIFYSCRIPT);
	  }
	  return 1;
	}
      } else if (sig[0] == 0x8e && sig[1] == 0xad && sig[2] == 0xe8 && sig[3] == 0x01) {
	FD_t fd = fdDup(d);

	close(d);
	if (fd != NULL) {
	  if (pkg->h && !(pkg->flag & FLAG_NO_HEADER_FREE)) headerFree(pkg->h);
	  pkg->h = headerRead(fd, HEADER_MAGIC_YES);
	  pkg->flag &= ~FLAG_NO_HEADER_FREE;
	  fdClose(fd);
	  return 1;
	}
      }
    }
  }
  return 0;
}

static void
read_config_files(int force) {
  static int already = 0;

  if (!already || force) {
    rpmReadConfigFiles(NULL, NULL);
    already = 1;
  }
}

static void *rpmRunTransactions_callback(const void *h,
					 const rpmCallbackType what,
					 const unsigned long amount,
					 const unsigned long total,
					 const void * pkgKey,
					 void * data) {
  static struct timeval tprev;
  static struct timeval tcurr;
  static FD_t fd = NULL;
  long delta;
  int i;
  struct s_TransactionData *td = data;
  SV *callback = NULL;
  char *callback_type = NULL;
  char *callback_subtype = NULL;

  switch (what) {
  case RPMCALLBACK_INST_OPEN_FILE:
    callback = td->callback_open; callback_type = "open"; break;

  case RPMCALLBACK_INST_CLOSE_FILE:
    callback = td->callback_close; callback_type = "close"; break;

  case RPMCALLBACK_TRANS_START:
  case RPMCALLBACK_TRANS_PROGRESS:
  case RPMCALLBACK_TRANS_STOP:
    callback = td->callback_trans; callback_type = "trans"; break;

  case RPMCALLBACK_UNINST_START:
  case RPMCALLBACK_UNINST_PROGRESS:
  case RPMCALLBACK_UNINST_STOP:
    callback = td->callback_uninst; callback_type = "uninst"; break;

  case RPMCALLBACK_INST_START:
  case RPMCALLBACK_INST_PROGRESS:
    callback = td->callback_inst; callback_type = "inst"; break;

  default:
    break;
  }

  if (callback != NULL) {
    switch (what) {
    case RPMCALLBACK_TRANS_START:
    case RPMCALLBACK_UNINST_START:
    case RPMCALLBACK_INST_START:
      callback_subtype = "start"; break;
      gettimeofday(&tprev, NULL);

    case RPMCALLBACK_TRANS_PROGRESS:
    case RPMCALLBACK_UNINST_PROGRESS:
    case RPMCALLBACK_INST_PROGRESS:
      callback_subtype = "progress";
      gettimeofday(&tcurr, NULL);
      delta = 1000000 * (tcurr.tv_sec - tprev.tv_sec) + (tcurr.tv_usec - tprev.tv_usec);
      if (delta < td->min_delta && amount < total - 1)
	callback = NULL; /* avoid calling too often a given callback */
      else
	tprev = tcurr;
      break;

    case RPMCALLBACK_TRANS_STOP:
    case RPMCALLBACK_UNINST_STOP:
      callback_subtype = "stop"; break;

    default:
      break;
    }

    if (callback != NULL) {
      /* now, a callback will be called for sure */
      dSP;
      ENTER;
      SAVETMPS;
      PUSHMARK(SP);
      XPUSHs(td->data);
      XPUSHs(sv_2mortal(newSVpv(callback_type, 0)));
      XPUSHs(pkgKey != NULL ? sv_2mortal(newSViv((int)pkgKey - 1)) : &PL_sv_undef);
      if (callback_subtype != NULL) {
	XPUSHs(sv_2mortal(newSVpv(callback_subtype, 0)));
	XPUSHs(sv_2mortal(newSViv(amount)));
	XPUSHs(sv_2mortal(newSViv(total)));
      }
      PUTBACK;
      i = call_sv(callback, callback == td->callback_open ? G_SCALAR : G_DISCARD);
      SPAGAIN;
      if (callback == td->callback_open) {
	if (i != 1) croak("callback_open should return a file handle");
	i = POPi;
	fd = fdDup(i);
	if (fd) {
	  fd = fdLink(fd, "persist perl-URPM");
	  Fcntl(fd, F_SETFD, (void *)1); /* necessary to avoid forked/execed process to lock removable */
	}
	PUTBACK;
      } else if (callback == td->callback_close) {
	fd = fdFree(fd, "persist perl-URPM");
	if (fd) {
	  fdClose(fd);
	  fd = NULL;
	}
      }
      FREETMPS;
      LEAVE;
    }
  }
  return callback == td->callback_open ? fd : NULL;
}


MODULE = URPM            PACKAGE = URPM::Package       PREFIX = Pkg_

void
Pkg_DESTROY(pkg)
  URPM::Package pkg
  CODE:
  free(pkg->info);
  free(pkg->requires);
  free(pkg->obsoletes);
  free(pkg->conflicts);
  free(pkg->provides);
  free(pkg->rflags);
  free(pkg->summary);
  if (pkg->h && !(pkg->flag & FLAG_NO_HEADER_FREE)) headerFree(pkg->h);
  free(pkg);

void
Pkg_name(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->info) {
    char *name;
    char *version;

    get_fullname_parts(pkg, &name, &version, NULL, NULL, NULL);
    if (version - name < 1) croak("invalid fullname");
    XPUSHs(sv_2mortal(newSVpv(name, version-name-1)));
  } else if (pkg->h) {
    XPUSHs(sv_2mortal(newSVpv(get_name(pkg->h, RPMTAG_NAME), 0)));
  }

void
Pkg_version(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->info) {
    char *version;
    char *release;

    get_fullname_parts(pkg, NULL, &version, &release, NULL, NULL);
    if (release - version < 1) croak("invalid fullname");
    XPUSHs(sv_2mortal(newSVpv(version, release-version-1)));
  } else if (pkg->h) {
    XPUSHs(sv_2mortal(newSVpv(get_name(pkg->h, RPMTAG_VERSION), 0)));
  }

void
Pkg_release(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->info) {
    char *release;
    char *arch;

    get_fullname_parts(pkg, NULL, NULL, &release, &arch, NULL);
    if (arch - release < 1) croak("invalid fullname");
    XPUSHs(sv_2mortal(newSVpv(release, arch-release-1)));
  } else if (pkg->h) {
    XPUSHs(sv_2mortal(newSVpv(get_name(pkg->h, RPMTAG_RELEASE), 0)));
  }

void
Pkg_arch(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->info) {
    char *arch;
    char *eos;

    get_fullname_parts(pkg, NULL, NULL, NULL, &arch, &eos);
    XPUSHs(sv_2mortal(newSVpv(arch, eos-arch)));
  } else if (pkg->h) {
    XPUSHs(sv_2mortal(newSVpv(headerIsEntry(pkg->h, RPMTAG_SOURCEPACKAGE) ? "src" : get_name(pkg->h, RPMTAG_ARCH), 0)));
  }

int
Pkg_is_arch_compat(pkg)
  URPM::Package pkg
  CODE:
  read_config_files(0);
  if (pkg->info) {
    char *arch;
    char *eos;

    get_fullname_parts(pkg, NULL, NULL, NULL, &arch, &eos);
    *eos = 0;
    RETVAL = rpmMachineScore(RPM_MACHTABLE_INSTARCH, arch);
    *eos = '@';
  } else if (pkg->h && !headerIsEntry(pkg->h, RPMTAG_SOURCEPACKAGE)) {
    RETVAL = rpmMachineScore(RPM_MACHTABLE_INSTARCH, get_name(pkg->h, RPMTAG_ARCH));
  } else {
    RETVAL = 0;
  }
  OUTPUT:
  RETVAL

void
Pkg_summary(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->summary) {
    XPUSHs(sv_2mortal(newSVpv(pkg->summary, 0)));
  } else if (pkg->h) {
    XPUSHs(sv_2mortal(newSVpv(get_name(pkg->h, RPMTAG_SUMMARY), 0)));
  }

void
Pkg_description(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->h) {
    XPUSHs(sv_2mortal(newSVpv(get_name(pkg->h, RPMTAG_DESCRIPTION), 0)));
  }

void
Pkg_sourcerpm(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->h) {
    XPUSHs(sv_2mortal(newSVpv(get_name(pkg->h, RPMTAG_SOURCERPM), 0)));
  }

void
Pkg_packager(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->h) {
    XPUSHs(sv_2mortal(newSVpv(get_name(pkg->h, RPMTAG_PACKAGER), 0)));
  }

void
Pkg_buildhost(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->h) {
    XPUSHs(sv_2mortal(newSVpv(get_name(pkg->h, RPMTAG_BUILDHOST), 0)));
  }

int
Pkg_buildtime(pkg)
  URPM::Package pkg
  CODE:
  if (pkg->h) {
    RETVAL = get_int(pkg->h, RPMTAG_BUILDTIME);
  } else {
    RETVAL = 0;
  }
  OUTPUT:
  RETVAL

int
Pkg_installtid(pkg)
  URPM::Package pkg
  CODE:
  if (pkg->h) {
    RETVAL = get_int(pkg->h, RPMTAG_INSTALLTID);
  } else {
    RETVAL = 0;
  }
  OUTPUT:
  RETVAL

void
Pkg_url(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->h) {
    XPUSHs(sv_2mortal(newSVpv(get_name(pkg->h, RPMTAG_URL), 0)));
  }

void
Pkg_license(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->h) {
    XPUSHs(sv_2mortal(newSVpv(get_name(pkg->h, RPMTAG_LICENSE), 0)));
  }

void
Pkg_distribution(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->h) {
    XPUSHs(sv_2mortal(newSVpv(get_name(pkg->h, RPMTAG_DISTRIBUTION), 0)));
  }

void
Pkg_vendor(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->h) {
    XPUSHs(sv_2mortal(newSVpv(get_name(pkg->h, RPMTAG_VENDOR), 0)));
  }

void
Pkg_os(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->h) {
    XPUSHs(sv_2mortal(newSVpv(get_name(pkg->h, RPMTAG_OS), 0)));
  }

void
Pkg_payload_format(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->h) {
    XPUSHs(sv_2mortal(newSVpv(get_name(pkg->h, RPMTAG_PAYLOADFORMAT), 0)));
  }

void
Pkg_fullname(pkg)
  URPM::Package pkg
  PREINIT:
  I32 gimme = GIMME_V;
  PPCODE:
  if (pkg->info) {
    if (gimme == G_SCALAR) {
      char *eos;
      if ((eos = strchr(pkg->info, '@')) != NULL) {
	XPUSHs(sv_2mortal(newSVpv(pkg->info, eos-pkg->info)));
      }
    } else if (gimme == G_ARRAY) {
      char *name, *version, *release, *arch, *eos;
      get_fullname_parts(pkg, &name, &version, &release, &arch, &eos);
      if (version - name < 1 || release - version < 1 || arch - release < 1)
	  croak("invalid fullname");
      EXTEND(SP, 4);
      PUSHs(sv_2mortal(newSVpv(name, version-name-1)));
      PUSHs(sv_2mortal(newSVpv(version, release-version-1)));
      PUSHs(sv_2mortal(newSVpv(release, arch-release-1)));
      PUSHs(sv_2mortal(newSVpv(arch, eos-arch)));
    }
  } else if (pkg->h) {
    char *name = get_name(pkg->h, RPMTAG_NAME);
    char *version = get_name(pkg->h, RPMTAG_VERSION);
    char *release = get_name(pkg->h, RPMTAG_RELEASE);
    char *arch = headerIsEntry(pkg->h, RPMTAG_SOURCEPACKAGE) ? "src" : get_name(pkg->h, RPMTAG_ARCH);

    if (gimme == G_SCALAR) {
      XPUSHs(sv_2mortal(newSVpvf("%s-%s-%s.%s", name, version, release, arch)));
    } else if (gimme == G_ARRAY) {
      EXTEND(SP, 4);
      PUSHs(sv_2mortal(newSVpv(name, 0)));
      PUSHs(sv_2mortal(newSVpv(version, 0)));
      PUSHs(sv_2mortal(newSVpv(release, 0)));
      PUSHs(sv_2mortal(newSVpv(arch, 0)));
    }
  }

int
Pkg_epoch(pkg)
  URPM::Package pkg
  CODE:
  if (pkg->info) {
    char *s, *eos;

    if ((s = strchr(pkg->info, '@')) != NULL) {
      if ((eos = strchr(s+1, '@')) != NULL) *eos = 0; /* mark end of string to enable searching backwards */
      RETVAL = atoi(s+1);
      if (eos != NULL) *eos = '@';
    } else {
      RETVAL = 0;
    }
  } else if (pkg->h) {
    RETVAL = get_int(pkg->h, RPMTAG_EPOCH);
  } else RETVAL = 0;
  OUTPUT:
  RETVAL

int
Pkg_compare_pkg(lpkg, rpkg)
  URPM::Package lpkg
  URPM::Package rpkg
  PREINIT:
  int compare = 0;
  int lepoch;
  char *lversion;
  char *lrelease;
  char *larch;
  char *leos;
  int repoch;
  char *rversion;
  char *rrelease;
  char *rarch;
  char *reos;
  CODE:
  if (lpkg == rpkg) RETVAL = 0;
  else {
    if (lpkg->info) {
      char *s;

      if ((s = strchr(lpkg->info, '@')) != NULL) {
	if ((leos = strchr(s+1, '@')) != NULL) *leos = 0; /* mark end of string to enable searching backwards */
	lepoch = atoi(s+1);
	if (leos != NULL) *leos = '@';
      } else {
	lepoch = 0;
      }
      get_fullname_parts(lpkg, NULL, &lversion, &lrelease, &larch, &leos);
      /* temporarily mark end of each substring */
      lrelease[-1] = 0;
      larch[-1] = 0;
    } else if (lpkg->h) {
      lepoch = get_int(lpkg->h, RPMTAG_EPOCH);
      lversion = get_name(lpkg->h, RPMTAG_VERSION);
      lrelease = get_name(lpkg->h, RPMTAG_RELEASE);
      larch = headerIsEntry(lpkg->h, RPMTAG_SOURCEPACKAGE) ? "src" : get_name(lpkg->h, RPMTAG_ARCH);
    } else croak("undefined package");
    if (rpkg->info) {
      char *s;

      if ((s = strchr(rpkg->info, '@')) != NULL) {
	if ((reos = strchr(s+1, '@')) != NULL) *reos = 0; /* mark end of string to enable searching backwards */
	repoch = atoi(s+1);
	if (reos != NULL) *reos = '@';
      } else {
	repoch = 0;
      }
      get_fullname_parts(rpkg, NULL, &rversion, &rrelease, &rarch, &reos);
      /* temporarily mark end of each substring */
      rrelease[-1] = 0;
      rarch[-1] = 0;
    } else if (rpkg->h) {
      repoch = get_int(rpkg->h, RPMTAG_EPOCH);
      rversion = get_name(rpkg->h, RPMTAG_VERSION);
      rrelease = get_name(rpkg->h, RPMTAG_RELEASE);
      rarch = headerIsEntry(rpkg->h, RPMTAG_SOURCEPACKAGE) ? "src" : get_name(rpkg->h, RPMTAG_ARCH);
    } else {
      /* restore info string modified */
      if (lpkg->info) {
	lrelease[-1] = '-';
	larch[-1] = '.';
      }
      croak("undefined package");
    }
    compare = lepoch - repoch;
    if (!compare) {
      compare = rpmvercmp(lversion, rversion);
      if (!compare) {
	compare = rpmvercmp(lrelease, rrelease);
	if (!compare) {
	  int lscore, rscore;
	  char *eolarch = strchr(larch, '@');
	  char *eorarch = strchr(rarch, '@');

	  read_config_files(0);
	  if (eolarch) *eolarch = 0; lscore = rpmMachineScore(RPM_MACHTABLE_INSTARCH, larch);
	  if (eorarch) *eorarch = 0; rscore = rpmMachineScore(RPM_MACHTABLE_INSTARCH, rarch);
	  if (lscore == 0) {
	    if (rscore == 0)
	      compare = strcmp(larch, rarch);
	    else
	      compare = -1;
	  } else {
	    if (rscore == 0)
	      compare = 1;
	    else
	      compare = rscore - lscore; /* score are lower for better */
	  }
	  if (eolarch) *eolarch = '@';
	  if (eorarch) *eorarch = '@';
	}
      }
    }
    /* restore info string modified */
    if (lpkg->info) {
      lrelease[-1] = '-';
      larch[-1] = '.';
    }
    if (rpkg->info) {
      rrelease[-1] = '-';
      rarch[-1] = '.';
    }
    RETVAL = compare;
  }
  OUTPUT:
  RETVAL

int
Pkg_compare(pkg, evr)
  URPM::Package pkg
  char *evr
  PREINIT:
  int compare = 0;
  int _epoch;
  char *_version;
  char *_release;
  char *_eos;
  CODE:
  if (pkg->info) {
    char *s;

    if ((s = strchr(pkg->info, '@')) != NULL) {
      if ((_eos = strchr(s+1, '@')) != NULL) *_eos = 0; /* mark end of string to enable searching backwards */
      _epoch = atoi(s+1);
      if (_eos != NULL) *_eos = '@';
    } else {
      _epoch = 0;
    }
    get_fullname_parts(pkg, NULL, &_version, &_release, &_eos, NULL);
    /* temporarily mark end of each substring */
    _release[-1] = 0;
    _eos[-1] = 0;
  } else if (pkg->h) {
    _epoch = get_int(pkg->h, RPMTAG_EPOCH);
  } else croak("undefined package");
  if (!compare) {
    char *epoch, *version, *release;

    /* extract epoch and version from evr */
    version = evr;
    while (*version && isdigit(*version)) version++;
    if (*version == ':') {
      epoch = evr;
      *version++ = 0;
      if (!*epoch) epoch = "0";
      compare = _epoch - (*epoch ? atoi(epoch) : 0);
      version[-1] = ':'; /* restore in memory modification */
    } else {
      /* there is no epoch defined, so no check on epoch and assume equality */
      version = evr;
    }
    if (!compare) {
      if (!pkg->info)
	_version = get_name(pkg->h, RPMTAG_VERSION);
      /* continue extracting release if any */
      if ((release = strrchr(version, '-')) != NULL) {
	*release++ = 0;
	compare = rpmvercmp(_version, version);
	if (!compare) {
	  /* need to compare with release here */
	  if (!pkg->info)
	    _release = get_name(pkg->h, RPMTAG_RELEASE);
	  compare = rpmvercmp(_release, release);
	}
	release[-1] = '-'; /* restore in memory modification */
      } else {
	compare = rpmvercmp(_version, version);
      }
    }
  }
  /* restore info string modified */
  if (pkg->info) {
    _release[-1] = '-';
    _eos[-1] = '.';
  }
  RETVAL = compare;
  OUTPUT:
  RETVAL

int
Pkg_size(pkg)
  URPM::Package pkg
  CODE:
  if (pkg->info) {
    char *s, *eos;

    if ((s = strchr(pkg->info, '@')) != NULL && (s = strchr(s+1, '@')) != NULL) {
      if ((eos = strchr(s+1, '@')) != NULL) *eos = 0; /* mark end of string to enable searching backwards */
      RETVAL = atoi(s+1);
      if (eos != NULL) *eos = '@';
    } else {
      RETVAL = 0;
    }
  } else if (pkg->h) {
    RETVAL = get_int(pkg->h, RPMTAG_SIZE);
  } else RETVAL = 0;
  OUTPUT:
  RETVAL

void
Pkg_group(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->info) {
    char *s;

    if ((s = strchr(pkg->info, '@')) != NULL && (s = strchr(s+1, '@')) != NULL && (s = strchr(s+1, '@')) != NULL) {
      char *eos = strchr(s+1, '@');
      XPUSHs(sv_2mortal(newSVpv(s+1, eos != NULL ? eos-s-1 : 0)));
    }
  } else if (pkg->h) {
    XPUSHs(sv_2mortal(newSVpv(get_name(pkg->h, RPMTAG_GROUP), 0)));
  }

void
Pkg_filename(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->info) {
    char *s, *eon, *eos;

    if ((eon = strchr(pkg->info, '@')) != NULL) {
      if ((s = strchr(eon+1, '@')) != NULL && (s = strchr(s+1, '@')) != NULL && (s = strchr(s+1, '@')) != NULL) {
	eos = strchr(s+1, '@');
	XPUSHs(sv_2mortal(newSVpv(s+1, eos != NULL ? eos-s-1 : 0)));
      } else {
	char savbuf[4];
	memcpy(savbuf, eon, 4); /* there should be at least epoch and size described so (@0@0 minimum) */
	memcpy(eon, ".rpm", 4);
	XPUSHs(sv_2mortal(newSVpv(pkg->info, eon-pkg->info+4)));
	memcpy(eon, savbuf, 4);
      }
    }
  } else if (pkg->h) {
    char *filename = get_name(pkg->h, FILENAME_TAG);

    if (filename != NULL)
      XPUSHs(sv_2mortal(newSVpv(filename, 0)));
  }

void
Pkg_header_filename(pkg)
  URPM::Package pkg
  PPCODE:
  if (pkg->info) {
    char *s, *eon, *eos;

    if ((eon = strchr(pkg->info, '@')) != NULL) {
      if ((s = strchr(eon+1, '@')) != NULL && (s = strchr(s+1, '@')) != NULL && (s = strchr(s+1, '@')) != NULL) {
	eos = strstr(s+1, ".rpm");
	if (eos != NULL) *eos = 0;
	if (eon != NULL) *eon = 0;
	XPUSHs(sv_2mortal(newSVpvf("%s:%s", pkg->info, s+1)));
	if (eon != NULL) *eon = '@';
	if (eos != NULL) *eos = '.';
      } else {
	XPUSHs(sv_2mortal(newSVpv(pkg->info, eon-pkg->info)));
      }
    }
  } else if (pkg->h) {
    char buff[1024];
    char *p = buff;
    char *name = get_name(pkg->h, RPMTAG_NAME);
    char *version = get_name(pkg->h, RPMTAG_VERSION);
    char *release = get_name(pkg->h, RPMTAG_RELEASE);
    char *arch = headerIsEntry(pkg->h, RPMTAG_SOURCEPACKAGE) ? "src" : get_name(pkg->h, RPMTAG_ARCH);
    char *filename = get_name(pkg->h, FILENAME_TAG);

    p += snprintf(buff, sizeof(buff), "%s-%s-%s.%s:", name, version, release, arch);
    if (filename) snprintf(p, sizeof(buff) - (p-buff), "%s-%s-%s.%s.rpm", name, version, release, arch);
    if (!filename || !strcmp(p, filename)) {
      *--p = 0;
    } else {
      p += snprintf(p, sizeof(buff) - (p-buff), "%s", filename);
      *(p -= 4) = 0; /* avoid .rpm */
    }
    XPUSHs(sv_2mortal(newSVpv(buff, p-buff)));
  }

void
Pkg_id(pkg)
  URPM::Package pkg
  PPCODE:
  if ((pkg->flag & FLAG_ID) <= FLAG_ID_MAX) {
    XPUSHs(sv_2mortal(newSViv(pkg->flag & FLAG_ID)));
  }

void
Pkg_set_id(pkg, id=-1)
  URPM::Package pkg
  int id
  PPCODE:
  if ((pkg->flag & FLAG_ID) <= FLAG_ID_MAX) {
    XPUSHs(sv_2mortal(newSViv(pkg->flag & FLAG_ID)));
  }
  pkg->flag &= ~FLAG_ID;
  pkg->flag |= id >= 0 && id <= FLAG_ID_MAX ? id : FLAG_ID_INVALID;

void
Pkg_requires(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_str(pkg->requires, pkg->h, RPMTAG_REQUIRENAME, RPMTAG_REQUIREFLAGS, RPMTAG_REQUIREVERSION,
		  callback_list_str_xpush, NULL);
  SPAGAIN;

void
Pkg_requires_nosense(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_str(pkg->requires, pkg->h, RPMTAG_REQUIRENAME, 0, 0, callback_list_str_xpush, NULL);
  SPAGAIN;

void
Pkg_obsoletes(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_str(pkg->obsoletes, pkg->h, RPMTAG_OBSOLETENAME, RPMTAG_OBSOLETEFLAGS, RPMTAG_OBSOLETEVERSION,
		  callback_list_str_xpush, NULL);
  SPAGAIN;

void
Pkg_obsoletes_nosense(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_str(pkg->obsoletes, pkg->h, RPMTAG_OBSOLETENAME, 0, 0, callback_list_str_xpush, NULL);
  SPAGAIN;

int
Pkg_obsoletes_overlap(pkg, s, b_nopromote=1, direction=-1)
  URPM::Package pkg
  char *s
  int b_nopromote
  int direction
  PREINIT:
  struct cb_overlap_s os;
  char *eon = NULL;
  char eonc = '\0';
  CODE:
  os.name = s;
  os.flags = 0;
  while (*s && *s != ' ' && *s != '[' && *s != '<' && *s != '>' && *s != '=') ++s;
  if (*s) {
    eon = s;
    while (*s) {
      if (*s == ' ' || *s == '[' || *s == '*' || *s == ']');
      else if (*s == '<') os.flags |= RPMSENSE_LESS;
      else if (*s == '>') os.flags |= RPMSENSE_GREATER;
      else if (*s == '=') os.flags |= RPMSENSE_EQUAL;
      else break;
      ++s;
    }
    os.evr = s;
  } else
    os.evr = "";
  os.direction = direction;
  os.b_nopromote = b_nopromote;
  /* mark end of name */
  if (eon) { eonc = *eon; *eon = 0; }
  /* return_list_str returns a negative value is the callback has returned non-zero */
  RETVAL = return_list_str(pkg->obsoletes, pkg->h, RPMTAG_OBSOLETENAME, RPMTAG_OBSOLETEFLAGS, RPMTAG_OBSOLETEVERSION,
			   callback_list_str_overlap, &os) < 0;
  /* restore end of name */
  if (eon) *eon = eonc;
  OUTPUT:
  RETVAL

void
Pkg_conflicts(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_str(pkg->conflicts, pkg->h, RPMTAG_CONFLICTNAME, RPMTAG_CONFLICTFLAGS, RPMTAG_CONFLICTVERSION,
		  callback_list_str_xpush, NULL);
  SPAGAIN;

void
Pkg_conflicts_nosense(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_str(pkg->conflicts, pkg->h, RPMTAG_CONFLICTNAME, 0, 0, callback_list_str_xpush, NULL);
  SPAGAIN;

void
Pkg_provides(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_str(pkg->provides, pkg->h, RPMTAG_PROVIDENAME, RPMTAG_PROVIDEFLAGS, RPMTAG_PROVIDEVERSION,
		  callback_list_str_xpush, NULL);
  SPAGAIN;

void
Pkg_provides_nosense(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_str(pkg->provides, pkg->h, RPMTAG_PROVIDENAME, 0, 0, callback_list_str_xpush, NULL);
  SPAGAIN;

int
Pkg_provides_overlap(pkg, s, b_nopromote=1, direction=1)
  URPM::Package pkg
  char *s
  int b_nopromote
  int direction
  PREINIT:
  struct cb_overlap_s os;
  char *eon = NULL;
  char eonc = '\0';
  CODE:
  os.name = s;
  os.flags = 0;
  while (*s && *s != ' ' && *s != '[' && *s != '<' && *s != '>' && *s != '=') ++s;
  if (*s) {
    eon = s;
    while (*s) {
      if (*s == ' ' || *s == '[' || *s == '*' || *s == ']');
      else if (*s == '<') os.flags |= RPMSENSE_LESS;
      else if (*s == '>') os.flags |= RPMSENSE_GREATER;
      else if (*s == '=') os.flags |= RPMSENSE_EQUAL;
      else break;
      ++s;
    }
    os.evr = s;
  } else
    os.evr = "";
  os.direction = direction;
  os.b_nopromote = b_nopromote;
  /* mark end of name */
  if (eon) { eonc = *eon; *eon = 0; }
  /* return_list_str returns a negative value is the callback has returned non-zero */
  RETVAL = return_list_str(pkg->provides, pkg->h, RPMTAG_PROVIDENAME, RPMTAG_PROVIDEFLAGS, RPMTAG_PROVIDEVERSION,
			   callback_list_str_overlap, &os) < 0;
  /* restore end of name */
  if (eon) *eon = eonc;
  OUTPUT:
  RETVAL

void
Pkg_buildarchs(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_str(NULL, pkg->h, RPMTAG_BUILDARCHS, 0, 0, callback_list_str_xpush, NULL);
  SPAGAIN;
  
void
Pkg_excludearchs(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_str(NULL, pkg->h, RPMTAG_EXCLUDEARCH, 0, 0, callback_list_str_xpush, NULL);
  SPAGAIN;
  
void
Pkg_exclusivearchs(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_str(NULL, pkg->h, RPMTAG_EXCLUSIVEARCH, 0, 0, callback_list_str_xpush, NULL);
  SPAGAIN;
  
void
Pkg_files(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_files(pkg->h, 0);
  SPAGAIN;

void
Pkg_files_md5sum(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_str(NULL, pkg->h, RPMTAG_FILEMD5S, 0, 0, callback_list_str_xpush, NULL);
  SPAGAIN;

void
Pkg_files_owner(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_str(NULL, pkg->h, RPMTAG_FILEUSERNAME, 0, 0, callback_list_str_xpush, NULL);
  SPAGAIN;

void
Pkg_files_group(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_str(NULL, pkg->h, RPMTAG_FILEGROUPNAME, 0, 0, callback_list_str_xpush, NULL);
  SPAGAIN;

void
Pkg_files_mtime(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_int_32(pkg->h, RPMTAG_FILEMTIMES);
  SPAGAIN;

void
Pkg_files_size(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_int_32(pkg->h, RPMTAG_FILESIZES);
  SPAGAIN;

void
Pkg_files_uid(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_int_32(pkg->h, RPMTAG_FILEUIDS);
  SPAGAIN;

void
Pkg_files_gid(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_int_32(pkg->h, RPMTAG_FILEGIDS);
  SPAGAIN;

void
Pkg_files_mode(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_uint_16(pkg->h, RPMTAG_FILEMODES);
  SPAGAIN;

void
Pkg_files_flags(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_int_32(pkg->h, RPMTAG_FILEFLAGS);
  SPAGAIN;
  
void
Pkg_conf_files(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_files(pkg->h, FILTER_MODE_CONF_FILES);
  SPAGAIN;

void
Pkg_upgrade_files(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_files(pkg->h, FILTER_MODE_UPGRADE_FILES);
  SPAGAIN;

void
Pkg_changelog_time(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_int_32(pkg->h, RPMTAG_CHANGELOGTIME);
  SPAGAIN;

void
Pkg_changelog_name(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_str(NULL, pkg->h, RPMTAG_CHANGELOGNAME, 0, 0, callback_list_str_xpush, NULL);
  SPAGAIN;

void
Pkg_changelog_text(pkg)
  URPM::Package pkg
  PPCODE:
  PUTBACK;
  return_list_str(NULL, pkg->h, RPMTAG_CHANGELOGTEXT, 0, 0, callback_list_str_xpush, NULL);
  SPAGAIN;

void
Pkg_queryformat(pkg, fmt)
  URPM::Package pkg
  char *fmt
  PREINIT:
  char *s;
  PPCODE:
  if (pkg->h) {
      s = headerSprintf(pkg->h, fmt,
    	rpmTagTable, rpmHeaderFormats, NULL);
      if (s) {
        XPUSHs(sv_2mortal(newSVpv(s,0)));
      }
  }
  
void
Pkg_get_tag(pkg, tagname)
  URPM::Package pkg
  int tagname;
  PPCODE:
  PUTBACK;
  return_list_tag(pkg, tagname);
  SPAGAIN;

void
Pkg_get_tag_modifiers(pkg, tagname)
  URPM::Package pkg
  int tagname;
  PPCODE:
  PUTBACK;
  return_list_tag_modifier(pkg->h, tagname);
  SPAGAIN;
  
void
Pkg_pack_header(pkg)
  URPM::Package pkg
  CODE:
  pack_header(pkg);

int
Pkg_update_header(pkg, filename, ...)
  URPM::Package pkg
  char *filename
  PREINIT:
  int packing = 0;
  int keep_all_tags = 0;
  CODE:
  /* compability mode with older interface of parse_hdlist */
  if (items == 3) {
    packing = SvIV(ST(2));
  } else if (items > 3) {
    int i;
    for (i = 2; i < items-1; i+=2) {
      STRLEN len;
      char *s = SvPV(ST(i), len);

      if (len == 7 && !memcmp(s, "packing", 7)) {
	packing = SvIV(ST(i + 1));
      } else if (len == 13 && !memcmp(s, "keep_all_tags", 13)) {
	keep_all_tags = SvIV(ST(i+1));
      }
    }
  }
  RETVAL = update_header(filename, pkg, !packing && keep_all_tags, RPMVSF_DEFAULT);
  if (RETVAL && packing) pack_header(pkg);
  OUTPUT:
  RETVAL

void
Pkg_free_header(pkg)
  URPM::Package pkg
  CODE:
  if (pkg->h && !(pkg->flag & FLAG_NO_HEADER_FREE)) headerFree(pkg->h);
  pkg->h = NULL;

void
Pkg_build_info(pkg, fileno, provides_files=NULL)
  URPM::Package pkg
  int fileno
  char *provides_files
  CODE:
  if (pkg->info) {
    char buff[65536];
    int size;

    /* info line should be the last to be written */
    if (pkg->provides && *pkg->provides) {
      size = snprintf(buff, sizeof(buff), "@provides@%s\n", pkg->provides);
      if (size < sizeof(buff)) {
	if (provides_files && *provides_files) {
	  --size;
	  size += snprintf(buff+size, sizeof(buff)-size, "@%s\n", provides_files);
	}
	write(fileno, buff, size);
      }
    }
    if (pkg->conflicts && *pkg->conflicts) {
      size = snprintf(buff, sizeof(buff), "@conflicts@%s\n", pkg->conflicts);
      if (size < sizeof(buff)) write(fileno, buff, size);
    }
    if (pkg->obsoletes && *pkg->obsoletes) {
      size = snprintf(buff, sizeof(buff), "@obsoletes@%s\n", pkg->obsoletes);
      if (size < sizeof(buff)) write(fileno, buff, size);
    }
    if (pkg->requires && *pkg->requires) {
      size = snprintf(buff, sizeof(buff), "@requires@%s\n", pkg->requires);
      if (size < sizeof(buff)) write(fileno, buff, size);
    }
    if (pkg->summary && *pkg->summary) {
      size = snprintf(buff, sizeof(buff), "@summary@%s\n", pkg->summary);
      if (size < sizeof(buff)) write(fileno, buff, size);
    }
    size = snprintf(buff, sizeof(buff), "@info@%s\n", pkg->info);
    write(fileno, buff, size);
  } else croak("no info available for package %s",
	  pkg->h ? get_name(pkg->h, RPMTAG_NAME) : "-");

void
Pkg_build_header(pkg, fileno)
  URPM::Package pkg
  int fileno
  CODE:
  if (pkg->h) {
    FD_t fd;

    if ((fd = fdDup(fileno)) != NULL) {
      headerWrite(fd, pkg->h, HEADER_MAGIC_YES);
      fdClose(fd);
    } else croak("unable to get rpmio handle on fileno %d", fileno);
  } else croak("no header available for package");

int
Pkg_flag(pkg, name)
  URPM::Package pkg
  char *name
  PREINIT:
  unsigned mask;
  CODE:
  if (!strcmp(name, "skip")) mask = FLAG_SKIP;
  else if (!strcmp(name, "disable_obsolete")) mask = FLAG_DISABLE_OBSOLETE;
  else if (!strcmp(name, "installed")) mask = FLAG_INSTALLED;
  else if (!strcmp(name, "requested")) mask = FLAG_REQUESTED;
  else if (!strcmp(name, "required")) mask = FLAG_REQUIRED;
  else if (!strcmp(name, "upgrade")) mask = FLAG_UPGRADE;
  else croak("unknown flag: %s", name);
  RETVAL = pkg->flag & mask;
  OUTPUT:
  RETVAL

int
Pkg_set_flag(pkg, name, value=1)
  URPM::Package pkg
  char *name
  int value
  PREINIT:
  unsigned mask;
  CODE:
  if (!strcmp(name, "skip")) mask = FLAG_SKIP;
  else if (!strcmp(name, "disable_obsolete")) mask = FLAG_DISABLE_OBSOLETE;
  else if (!strcmp(name, "installed")) mask = FLAG_INSTALLED;
  else if (!strcmp(name, "requested")) mask = FLAG_REQUESTED;
  else if (!strcmp(name, "required")) mask = FLAG_REQUIRED;
  else if (!strcmp(name, "upgrade")) mask = FLAG_UPGRADE;
  else croak("unknown flag: %s", name);
  RETVAL = pkg->flag & mask;
  if (value) pkg->flag |= mask;
  else       pkg->flag &= ~mask;
  OUTPUT:
  RETVAL

int
Pkg_flag_skip(pkg)
  URPM::Package pkg
  CODE:
  RETVAL = pkg->flag & FLAG_SKIP;
  OUTPUT:
  RETVAL

int
Pkg_set_flag_skip(pkg, value=1)
  URPM::Package pkg
  int value
  CODE:
  RETVAL = pkg->flag & FLAG_SKIP;
  if (value) pkg->flag |= FLAG_SKIP;
  else       pkg->flag &= ~FLAG_SKIP;
  OUTPUT:
  RETVAL

int
Pkg_flag_base(pkg)
  URPM::Package pkg
  CODE:
  RETVAL = pkg->flag & FLAG_BASE;
  OUTPUT:
  RETVAL

int
Pkg_set_flag_base(pkg, value=1)
  URPM::Package pkg
  int value
  CODE:
  RETVAL = pkg->flag & FLAG_BASE;
  if (value) pkg->flag |= FLAG_BASE;
  else       pkg->flag &= ~FLAG_BASE;
  OUTPUT:
  RETVAL

int
Pkg_flag_disable_obsolete(pkg)
  URPM::Package pkg
  CODE:
  RETVAL = pkg->flag & FLAG_DISABLE_OBSOLETE;
  OUTPUT:
  RETVAL

int
Pkg_set_flag_disable_obsolete(pkg, value=1)
  URPM::Package pkg
  int value
  CODE:
  RETVAL = pkg->flag & FLAG_DISABLE_OBSOLETE;
  if (value) pkg->flag |= FLAG_DISABLE_OBSOLETE;
  else       pkg->flag &= ~FLAG_DISABLE_OBSOLETE;
  OUTPUT:
  RETVAL

int
Pkg_flag_installed(pkg)
  URPM::Package pkg
  CODE:
  RETVAL = pkg->flag & FLAG_INSTALLED;
  OUTPUT:
  RETVAL

int
Pkg_set_flag_installed(pkg, value=1)
  URPM::Package pkg
  int value
  CODE:
  RETVAL = pkg->flag & FLAG_INSTALLED;
  if (value) pkg->flag |= FLAG_INSTALLED;
  else       pkg->flag &= ~FLAG_INSTALLED;
  OUTPUT:
  RETVAL

int
Pkg_flag_requested(pkg)
  URPM::Package pkg
  CODE:
  RETVAL = pkg->flag & FLAG_REQUESTED;
  OUTPUT:
  RETVAL

int
Pkg_set_flag_requested(pkg, value=1)
  URPM::Package pkg
  int value
  CODE:
  RETVAL = pkg->flag & FLAG_REQUESTED;
  if (value) pkg->flag |= FLAG_REQUESTED;
  else       pkg->flag &= ~FLAG_REQUESTED;
  OUTPUT:
  RETVAL

int
Pkg_flag_required(pkg)
  URPM::Package pkg
  CODE:
  RETVAL = pkg->flag & FLAG_REQUIRED;
  OUTPUT:
  RETVAL

int
Pkg_set_flag_required(pkg, value=1)
  URPM::Package pkg
  int value
  CODE:
  RETVAL = pkg->flag & FLAG_REQUIRED;
  if (value) pkg->flag |= FLAG_REQUIRED;
  else       pkg->flag &= ~FLAG_REQUIRED;
  OUTPUT:
  RETVAL

int
Pkg_flag_upgrade(pkg)
  URPM::Package pkg
  CODE:
  RETVAL = pkg->flag & FLAG_UPGRADE;
  OUTPUT:
  RETVAL

int
Pkg_set_flag_upgrade(pkg, value=1)
  URPM::Package pkg
  int value
  CODE:
  RETVAL = pkg->flag & FLAG_UPGRADE;
  if (value) pkg->flag |= FLAG_UPGRADE;
  else       pkg->flag &= ~FLAG_UPGRADE;
  OUTPUT:
  RETVAL

int
Pkg_flag_selected(pkg)
  URPM::Package pkg
  CODE:
  RETVAL = pkg->flag & FLAG_UPGRADE ? pkg->flag & (FLAG_BASE | FLAG_REQUIRED) : 0;
  OUTPUT:
  RETVAL

int
Pkg_flag_available(pkg)
  URPM::Package pkg
  CODE:
  RETVAL = (pkg->flag & FLAG_INSTALLED && !(pkg->flag & FLAG_UPGRADE)) ||
           (pkg->flag & FLAG_UPGRADE ? pkg->flag & (FLAG_BASE | FLAG_REQUIRED) : 0);
  OUTPUT:
  RETVAL

int
Pkg_rate(pkg)
  URPM::Package pkg
  CODE:
  RETVAL = (pkg->flag & FLAG_RATE) >> FLAG_RATE_POS;
  OUTPUT:
  RETVAL

int
Pkg_set_rate(pkg, rate)
  URPM::Package pkg
  int rate
  CODE:
  RETVAL = (pkg->flag & FLAG_RATE) >> FLAG_RATE_POS;
  pkg->flag &= ~FLAG_RATE;
  pkg->flag |= (rate >= 0 && rate <= FLAG_RATE_MAX ? rate : FLAG_RATE_INVALID) << FLAG_RATE_POS;
  OUTPUT:
  RETVAL

void
Pkg_rflags(pkg)
  URPM::Package pkg
  PREINIT:
  I32 gimme = GIMME_V;
  PPCODE:
  if (gimme == G_ARRAY && pkg->rflags != NULL) {
    char *s = pkg->rflags;
    char *eos;
    while ((eos = strchr(s, '\t')) != NULL) {
      XPUSHs(sv_2mortal(newSVpv(s, eos-s)));
      s = eos + 1;
    }
    XPUSHs(sv_2mortal(newSVpv(s, 0)));
  }

void
Pkg_set_rflags(pkg, ...)
  URPM::Package pkg
  PREINIT:
  I32 gimme = GIMME_V;
  char *new_rflags;
  STRLEN total_len;
  int i;
  PPCODE:
  total_len = 0;
  for (i = 1; i < items; ++i)
    total_len += SvCUR(ST(i)) + 1;

  new_rflags = malloc(total_len);
  total_len = 0;
  for (i = 1; i < items; ++i) {
    STRLEN len;
    char *s = SvPV(ST(i), len);
    memcpy(new_rflags + total_len, s, len);
    new_rflags[total_len + len] = '\t';
    total_len += len + 1;
  }
  new_rflags[total_len - 1] = 0; /* but mark end-of-string correctly */

  if (gimme == G_ARRAY && pkg->rflags != NULL) {
    char *s = pkg->rflags;
    char *eos;
    while ((eos = strchr(s, '\t')) != NULL) {
      XPUSHs(sv_2mortal(newSVpv(s, eos-s)));
      s = eos + 1;
    }
    XPUSHs(sv_2mortal(newSVpv(s, 0)));
  }

  free(pkg->rflags);
  pkg->rflags = new_rflags;


MODULE = URPM            PACKAGE = URPM::DB            PREFIX = Db_

URPM::DB
Db_open(prefix="", write_perm=0)
  char *prefix
  int write_perm
  PREINIT:
  URPM__DB db;
  CODE:
  read_config_files(0);
  db = malloc(sizeof(struct s_Transaction));
  db->ts = rpmtsCreate();
  db->count = 1;
  rpmtsSetRootDir(db->ts, prefix);
  RETVAL = rpmtsOpenDB(db->ts, write_perm ? O_RDWR | O_CREAT : O_RDONLY) == 0 ? db : NULL;
  OUTPUT:
  RETVAL

int
Db_rebuild(prefix="")
  char *prefix
  PREINIT:
  rpmts ts;
  CODE:
  read_config_files(0);
  ts = rpmtsCreate();
  rpmtsSetRootDir(ts, prefix);
  RETVAL = rpmtsRebuildDB(ts) == 0;
  rpmtsFree(ts);
  OUTPUT:
  RETVAL

void
Db_DESTROY(db)
  URPM::DB db
  CODE:
  if (--db->count <= 0) {
    rpmtsFree(db->ts);
    free(db);
  }

int
Db_traverse(db,callback)
  URPM::DB db
  SV *callback
  PREINIT:
  Header header;
  rpmdbMatchIterator mi;
  int count = 0;
  CODE:
  mi = rpmtsInitIterator(db->ts, RPMDBI_PACKAGES, NULL, 0);
  while ((header = rpmdbNextIterator(mi))) {
    if (SvROK(callback)) {
      dSP;
      URPM__Package pkg = calloc(1, sizeof(struct s_Package));

      pkg->flag = FLAG_ID_INVALID | FLAG_NO_HEADER_FREE;
      pkg->h = header;

      PUSHMARK(SP);
      XPUSHs(sv_2mortal(sv_setref_pv(newSVpv("", 0), "URPM::Package", pkg)));
      PUTBACK;

      call_sv(callback, G_DISCARD | G_SCALAR);

      SPAGAIN;
      pkg->h = 0; /* avoid using it anymore, in case it has been copied inside callback */
    }
    ++count;
  }
  rpmdbFreeIterator(mi);
  RETVAL = count;
  OUTPUT:
  RETVAL

int
Db_traverse_tag(db,tag,names,callback)
  URPM::DB db
  char *tag
  SV *names
  SV *callback
  PREINIT:
  Header header;
  rpmdbMatchIterator mi;
  int count = 0;
  CODE:
  if (SvROK(names) && SvTYPE(SvRV(names)) == SVt_PVAV) {
    AV* names_av = (AV*)SvRV(names);
    int len = av_len(names_av);
    int i, rpmtag;

    if (!strcmp(tag, "name"))
      rpmtag = RPMTAG_NAME;
    else if (!strcmp(tag, "whatprovides"))
      rpmtag = RPMTAG_PROVIDENAME;
    else if (!strcmp(tag, "whatrequires"))
      rpmtag = RPMTAG_REQUIRENAME;
    else if (!strcmp(tag, "whatconflicts"))
      rpmtag = RPMTAG_CONFLICTNAME;
    else if (!strcmp(tag, "group"))
      rpmtag = RPMTAG_GROUP;
    else if (!strcmp(tag, "triggeredby"))
      rpmtag = RPMTAG_BASENAMES;
    else if (!strcmp(tag, "path"))
      rpmtag = RPMTAG_BASENAMES;
    else croak("unknown tag");

    for (i = 0; i <= len; ++i) {
      STRLEN str_len;
      SV **isv = av_fetch(names_av, i, 0);
      char *name = SvPV(*isv, str_len);
      mi = rpmtsInitIterator(db->ts, rpmtag, name, str_len);
      while ((header = rpmdbNextIterator(mi))) {
	if (SvROK(callback)) {
	  dSP;
	  URPM__Package pkg = calloc(1, sizeof(struct s_Package));

	  pkg->flag = FLAG_ID_INVALID | FLAG_NO_HEADER_FREE;
	  pkg->h = header;

	  PUSHMARK(SP);
	  XPUSHs(sv_2mortal(sv_setref_pv(newSVpv("", 0), "URPM::Package", pkg)));
	  PUTBACK;

	  call_sv(callback, G_DISCARD | G_SCALAR);

	  SPAGAIN;
	  pkg->h = 0; /* avoid using it anymore, in case it has been copied inside callback */
	}
	++count;
      }
      rpmdbFreeIterator(mi);
    } 
  } else croak("bad arguments list");
  RETVAL = count;
  OUTPUT:
  RETVAL

URPM::Transaction
Db_create_transaction(db, prefix="/")
  URPM::DB db
  char *prefix
  CODE:
  /* this is *REALLY* dangerous to create a new transaction while another is open,
     so use the db transaction instead. */
  RETVAL = db;
  ++RETVAL->count;
  OUTPUT:
  RETVAL


MODULE = URPM            PACKAGE = URPM::Transaction   PREFIX = Trans_

void
Trans_DESTROY(trans)
  URPM::Transaction trans
  CODE:
  if (--trans->count <= 0) {
    rpmtsFree(trans->ts);
    free(trans);
  }

void
Trans_set_script_fd(trans, fdno)
  URPM::Transaction trans
  int fdno
  CODE:
  rpmtsSetScriptFd(trans->ts, fdDup(fdno));

int
Trans_add(trans, pkg, ...)
  URPM::Transaction trans
  URPM::Package pkg
  CODE:
  if ((pkg->flag & FLAG_ID) <= FLAG_ID_MAX && pkg->h != NULL) {
    int update = 0;
    rpmRelocation *relocations = NULL;
    /* compability mode with older interface of add */
    if (items == 3) {
      update = SvIV(ST(2));
    } else if (items > 3) {
      int i;
      for (i = 2; i < items-1; i+=2) {
	STRLEN len;
	char *s = SvPV(ST(i), len);

	if (len == 6 && !memcmp(s, "update", 6)) {
	  update = SvIV(ST(i+1));
	} else if (len == 11 && !memcmp(s, "excludepath", 11)) {
	  if (SvROK(ST(i+1)) && SvTYPE(SvRV(ST(i+1))) == SVt_PVAV) {
	    AV *excludepath = (AV*)SvRV(ST(i+1));
	    I32 j = 1 + av_len(excludepath);
	    relocations = calloc(2 + av_len(excludepath), sizeof(rpmRelocation));
	    while (--j >= 0) {
	      SV **e = av_fetch(excludepath, j, 0);
	      if (e != NULL && *e != NULL) {
		relocations[j].oldPath = SvPV_nolen(*e);
	      }
	    }
	  }
	}
      }
    }
    RETVAL = rpmtsAddInstallElement(trans->ts, pkg->h, (void *)(1+(pkg->flag & FLAG_ID)), update, relocations) == 0;
    /* free allocated memory, check rpm is copying it just above, at least in 4.0.4 */
    free(relocations);
  } else RETVAL = 0;
  OUTPUT:
  RETVAL

int
Trans_remove(trans, name)
  URPM::Transaction trans
  char *name
  PREINIT:
  Header h;
  rpmdbMatchIterator mi;
  int count = 0;
  char *boa = NULL, *bor = NULL;
  CODE:
  /* hide arch in name if present */
  if ((boa = strrchr(name, '.'))) {
    *boa = 0;
    if ((bor = strrchr(name, '-'))) {
      *bor = 0;
      if (!strrchr(name, '-')) {
	*boa = '.'; boa = NULL;
      }
      *bor = '-'; bor = NULL;
    } else {
      *boa = '.'; boa = NULL;
    }
  }
  mi = rpmtsInitIterator(trans->ts, RPMDBI_LABEL, name, 0);
  while ((h = rpmdbNextIterator(mi))) {
    unsigned int recOffset = rpmdbGetIteratorOffset(mi);
    if (recOffset != 0) {
      rpmtsAddEraseElement(trans->ts, h, recOffset);
      ++count;
    }
  }
  rpmdbFreeIterator(mi);
  if (boa) *boa = '.';
  RETVAL=count;
  OUTPUT:
  RETVAL

void
Trans_check(trans, ...)
  URPM::Transaction trans
  PREINIT:
  I32 gimme = GIMME_V;
  int translate_message = 0;
  int i;
  PPCODE:
  for (i = 1; i < items-1; i+=2) {
    STRLEN len;
    char *s = SvPV(ST(i), len);

    if (len == 17 && !memcmp(s, "translate_message", 17)) {
      translate_message = SvIV(ST(i+1));
    }
  }
  if (rpmtsCheck(trans->ts)) {
    if (gimme == G_SCALAR) {
      XPUSHs(sv_2mortal(newSViv(0)));
    } else if (gimme == G_ARRAY) {
      XPUSHs(sv_2mortal(newSVpv("error while checking dependencies", 0)));
    }
  } else {
    rpmps ps = rpmtsProblems(trans->ts);
    if (rpmpsNumProblems(ps) > 0) {
      if (gimme == G_SCALAR) {
	XPUSHs(sv_2mortal(newSViv(0)));
      } else if (gimme == G_ARRAY) {
	/* now translation is handled by rpmlib, but only for version 4.2 and above */
	PUTBACK;
	return_problems(ps, 1);
	SPAGAIN;
      }
    } else if (gimme == G_SCALAR) {
      XPUSHs(sv_2mortal(newSViv(1)));
    }
    ps = rpmpsFree(ps);
  }

void
Trans_order(trans)
  URPM::Transaction trans
  PREINIT:
  I32 gimme = GIMME_V;
  PPCODE:
  if (rpmtsOrder(trans->ts) == 0) {
    if (gimme == G_SCALAR) {
      XPUSHs(sv_2mortal(newSViv(1)));
    }
  } else {
    if (gimme == G_SCALAR) {
      XPUSHs(sv_2mortal(newSViv(0)));
    } else if (gimme == G_ARRAY) {
      XPUSHs(sv_2mortal(newSVpv("error while ordering dependencies", 0)));
    }
  }

void
Trans_run(trans, data, ...)
  URPM::Transaction trans
  SV *data
  PREINIT:
  struct s_TransactionData td = { NULL, NULL, NULL, NULL, NULL, 100000, data };
  rpmtransFlags transFlags = RPMTRANS_FLAG_NONE;
  int probFilter = 0;
  int translate_message = 0;
  int i;
  PPCODE:
  for (i = 2 ; i < items - 1 ; i += 2) {
    STRLEN len;
    char *s = SvPV(ST(i), len);

    if (len == 4 && !memcmp(s, "test", 4)) {
      if (SvIV(ST(i+1))) transFlags |= RPMTRANS_FLAG_TEST;
    } else if (len == 11 && !memcmp(s, "excludedocs", 11)) {
      if (SvIV(ST(i+1))) transFlags |= RPMTRANS_FLAG_NODOCS;
    } else if (len == 5) {
      if (!memcmp(s, "force", 5)) {
	if (SvIV(ST(i+1))) probFilter |= (RPMPROB_FILTER_REPLACEPKG |
					  RPMPROB_FILTER_REPLACEOLDFILES |
					  RPMPROB_FILTER_REPLACENEWFILES |
					  RPMPROB_FILTER_OLDPACKAGE);
      } else if (!memcmp(s, "delta", 5))
	td.min_delta = SvIV(ST(i+1));
    } else if (len == 6 && !memcmp(s, "nosize", 6)) {
      if (SvIV(ST(i+1))) probFilter |= (RPMPROB_FILTER_DISKSPACE|RPMPROB_FILTER_DISKNODES);
    } else if (len == 9 && !memcmp(s, "noscripts", 9)) {
      if (SvIV(ST(i+1))) transFlags |= (RPMTRANS_FLAG_NOSCRIPTS |
				        RPMTRANS_FLAG_NOPRE |
				        RPMTRANS_FLAG_NOPREUN |
				        RPMTRANS_FLAG_NOPOST |
				        RPMTRANS_FLAG_NOPOSTUN );
    } else if (len == 10 && !memcmp(s, "oldpackage", 10)) {
      if (SvIV(ST(i+1))) probFilter |= RPMPROB_FILTER_OLDPACKAGE;
    } else if (len == 9 && !memcmp(s, "repackage", 9)) {
      if (SvIV(ST(i+1))) transFlags |= RPMTRANS_FLAG_REPACKAGE;
    } else if (len == 10 && !memcmp(s, "ignorearch", 10)) {
      if (SvIV(ST(i+1))) probFilter |= RPMPROB_FILTER_IGNOREARCH;
    } else if (len == 17 && !memcmp(s, "translate_message", 17))
      translate_message = 1;
    else if (len >= 9 && !memcmp(s, "callback_", 9)) {
      if (len == 9+4 && !memcmp(s+9, "open", 4)) {
	if (SvROK(ST(i+1))) td.callback_open = ST(i+1);
      } else if (len == 9+5 && !memcmp(s+9, "close", 5)) {
	if (SvROK(ST(i+1))) td.callback_close = ST(i+1);
      } else if (len == 9+5 && !memcmp(s+9, "trans", 5)) {
	if (SvROK(ST(i+1))) td.callback_trans = ST(i+1);
      } else if (len == 9+6 && !memcmp(s+9, "uninst", 6)) {
	if (SvROK(ST(i+1))) td.callback_uninst = ST(i+1);
      } else if (len == 9+4 && !memcmp(s+9, "inst", 4)) {
	if (SvROK(ST(i+1))) td.callback_inst = ST(i+1);
      }
    }
  }
  /* check macros */
  {
    char *repa = rpmExpand("%_repackage_all_erasures", NULL);
    if (repa && *repa && *repa != '0')
      transFlags |= RPMTRANS_FLAG_REPACKAGE;
    if (repa) free(repa);
  }
  rpmtsSetFlags(trans->ts, transFlags);
  rpmtsSetNotifyCallback(trans->ts, rpmRunTransactions_callback, &td);
  if (rpmtsRun(trans->ts, NULL, probFilter) > 0) {
    rpmps ps = rpmtsProblems(trans->ts);
    PUTBACK;
    return_problems(ps, translate_message);
    SPAGAIN;
    ps = rpmpsFree(ps);
  }
  rpmtsEmpty(trans->ts);

MODULE = URPM            PACKAGE = URPM                PREFIX = Urpm_


void
Urpm_read_config_files()
  CODE:
  read_config_files(1); /* force re-read of configuration files */

void
Urpm_list_rpm_tag(urpm=Nullsv)
   SV *urpm
   PREINIT:
       int i = 0;
       const struct headerSprintfExtension_s * ext = rpmHeaderFormats;
   PPCODE:
       read_config_files(0);
      
       for (i = 0; i < rpmTagTableSize; i++) {
	XPUSHs(sv_2mortal(newSVpv(rpmTagTable[i].name + 7, 0)));
	XPUSHs(sv_2mortal(newSViv(rpmTagTable[i].val)));
       }

       while (ext->name != NULL) {
          if (ext->type == HEADER_EXT_MORE) {
		  ext = ext->u.more;
		  continue;
	  }
	  for (i = 0; i < rpmTagTableSize; i++) {
		  if (!strcmp(rpmTagTable[i].name, ext->name))
			  break;
	  }
	  if (i >= rpmTagTableSize && ext->type == HEADER_EXT_TAG) {
	  	XPUSHs(sv_2mortal(newSVpv(ext->name + 7, 0)));
	  	XPUSHs(sv_newmortal());
	  }
  	  ext++;
       }

int
rpmvercmp(one, two)
    char *one
    char *two        
       
int
Urpm_ranges_overlap(a, b, b_nopromote=1)
  char *a
  char *b
  int b_nopromote
  PREINIT:
  char *sa = a, *sb = b;
  int aflags = 0, bflags = 0;
  CODE:
  while (*sa && *sa != ' ' && *sa != '[' && *sa != '<' && *sa != '>' && *sa != '=' && *sa == *sb) {
    ++sa;
    ++sb;
  }
  if ((*sa && *sa != ' ' && *sa != '[' && *sa != '<' && *sa != '>' && *sa != '=') ||
      (*sb && *sb != ' ' && *sb != '[' && *sb != '<' && *sb != '>' && *sb != '=')) {
    /* the strings are sure to be different */
    RETVAL = 0;
  } else {
    while (*sa) {
      if (*sa == ' ' || *sa == '[' || *sa == '*' || *sa == ']');
      else if (*sa == '<') aflags |= RPMSENSE_LESS;
      else if (*sa == '>') aflags |= RPMSENSE_GREATER;
      else if (*sa == '=') aflags |= RPMSENSE_EQUAL;
      else break;
      ++sa;
    }
    while (*sb) {
      if (*sb == ' ' || *sb == '[' || *sb == '*' || *sb == ']');
      else if (*sb == '<') bflags |= RPMSENSE_LESS;
      else if (*sb == '>') bflags |= RPMSENSE_GREATER;
      else if (*sb == '=') bflags |= RPMSENSE_EQUAL;
      else break;
      ++sb;
    }
    RETVAL = ranges_overlap(aflags, sa, bflags, sb, b_nopromote);
  }
  OUTPUT:
  RETVAL

void
Urpm_parse_synthesis(urpm, filename, ...)
  SV *urpm
  char *filename
  PPCODE:
  if (SvROK(urpm) && SvTYPE(SvRV(urpm)) == SVt_PVHV) {
    SV **fdepslist = hv_fetch((HV*)SvRV(urpm), "depslist", 8, 0);
    AV *depslist = fdepslist && SvROK(*fdepslist) && SvTYPE(SvRV(*fdepslist)) == SVt_PVAV ? (AV*)SvRV(*fdepslist) : NULL;
    SV **fprovides = hv_fetch((HV*)SvRV(urpm), "provides", 8, 0);
    HV *provides = fprovides && SvROK(*fprovides) && SvTYPE(SvRV(*fprovides)) == SVt_PVHV ? (HV*)SvRV(*fprovides) : NULL;

    if (depslist != NULL) {
      char buff[65536];
      char *p, *eol;
      int buff_len;
      struct s_Package pkg;
      gzFile f;
      int start_id = 1 + av_len(depslist);
      SV *callback = NULL;

      if (items > 2) {
	int i;
	for (i = 2; i < items-1; i+=2) {
	  STRLEN len;
	  char *s = SvPV(ST(i), len);

	  if (len == 8 && !memcmp(s, "callback", 8)) {
	    if (SvROK(ST(i+1))) callback = ST(i+1);
	  }
	}
      }

      PUTBACK;
      if ((f = gzopen(filename, "rb")) != NULL) {
	memset(&pkg, 0, sizeof(struct s_Package));
	buff[sizeof(buff)-1] = 0;
	p = buff;
	while ((buff_len = gzread(f, p, sizeof(buff)-1-(p-buff)) + (p-buff)) != 0) {
	  p = buff;
	  if ((eol = strchr(p, '\n')) != NULL) {
	    do {
	      *eol++ = 0;
	      parse_line(depslist, provides, &pkg, p, urpm, callback);
	      p = eol;
	    } while ((eol = strchr(p, '\n')) != NULL);
	  } else {
	    /* a line larger than sizeof(buff) has been encountered, bad file problably */
	    break;
	  }
	  if (gzeof(f)) {
	    parse_line(depslist, provides, &pkg, p, urpm, callback);
	    break;
	  } else {
	    memmove(buff, p, buff_len-(p-buff));
	    p = &buff[buff_len-(p-buff)];
	  }
	}
	gzclose(f);
	SPAGAIN;
	if (av_len(depslist) >= start_id) {
	  XPUSHs(sv_2mortal(newSViv(start_id)));
	  XPUSHs(sv_2mortal(newSViv(av_len(depslist))));
	}
      } else {
	  SV **nofatal = hv_fetch((HV*)SvRV(urpm), "nofatal", 7, 0);
	  if (!errno) errno = EINVAL; /* zlib error */
	  if (!nofatal || !SvIV(*nofatal))
	      croak(errno == ENOENT
		      ? "unable to read synthesis file %s"
		      : "unable to uncompress synthesis file %s", filename);
      }
    } else croak("first argument should contain a depslist ARRAY reference");
  } else croak("first argument should be a reference to a HASH");

void
Urpm_parse_hdlist(urpm, filename, ...)
  SV *urpm
  char *filename
  PPCODE:
  if (SvROK(urpm) && SvTYPE(SvRV(urpm)) == SVt_PVHV) {
    SV **fdepslist = hv_fetch((HV*)SvRV(urpm), "depslist", 8, 0);
    AV *depslist = fdepslist && SvROK(*fdepslist) && SvTYPE(SvRV(*fdepslist)) == SVt_PVAV ? (AV*)SvRV(*fdepslist) : NULL;
    SV **fprovides = hv_fetch((HV*)SvRV(urpm), "provides", 8, 0);
    HV *provides = fprovides && SvROK(*fprovides) && SvTYPE(SvRV(*fprovides)) == SVt_PVHV ? (HV*)SvRV(*fprovides) : NULL;

    if (depslist != NULL) {
      pid_t pid;
      int d;
      FD_t fd;

      d = open_archive(filename, &pid);
      fd = fdDup(d);
      close(d);

      if (fdFileno(fd) >= 0) {
	Header header;
	int start_id = 1 + av_len(depslist);
	int packing = 0;
	SV *callback = NULL;

	/* compability mode with older interface of parse_hdlist */
	if (items == 3) {
	  packing = SvIV(ST(2));
	} else if (items > 3) {
	  int i;
	  for (i = 2; i < items-1; i+=2) {
	    STRLEN len;
	    char *s = SvPV(ST(i), len);

	    if (len == 7 && !memcmp(s, "packing", 7)) {
	      packing = SvIV(ST(i+1));
	    } else if (len == 8 && !memcmp(s, "callback", 8)) {
	      if (SvROK(ST(i+1))) callback = ST(i+1);
	    }
	  }
	}

	PUTBACK;
	do {
	  int count = 4;
	  header=headerRead(fd, HEADER_MAGIC_YES);
	  while (header == NULL && count > 0) {
	    fd_set readfds;
	    struct timeval timeout;

	    FD_ZERO(&readfds);
	    FD_SET(fdFileno(fd), &readfds);
	    timeout.tv_sec = 1;
	    timeout.tv_usec = 0;
	    select(fdFileno(fd)+1, &readfds, NULL, NULL, &timeout);

	    header=headerRead(fd, HEADER_MAGIC_YES);
	    --count;
	  }
	  if (header != NULL) {
	    struct s_Package pkg, *_pkg;
	    SV *sv_pkg;

	    memset(&pkg, 0, sizeof(struct s_Package));
	    pkg.flag = 1 + av_len(depslist);
	    pkg.h = header;
	    sv_pkg = sv_setref_pv(newSVpv("", 0), "URPM::Package",
				  _pkg = memcpy(malloc(sizeof(struct s_Package)), &pkg, sizeof(struct s_Package)));
	    if (call_package_callback(urpm, sv_pkg, callback)) {
	      if (provides) {
		update_provides(_pkg, provides);
		update_provides_files(_pkg, provides);
	      }
	      if (packing) pack_header(_pkg);
	      av_push(depslist, sv_pkg);
	    }
	  }
	} while (header != NULL);
	fdClose(fd);
	if (pid) {
	  kill(pid, SIGTERM);
	  waitpid(pid, NULL, 0);
	  pid = 0;
	}
	SPAGAIN;
	if (av_len(depslist) >= start_id) {
	  XPUSHs(sv_2mortal(newSViv(start_id)));
	  XPUSHs(sv_2mortal(newSViv(av_len(depslist))));
	}
      } else {
	  SV **nofatal = hv_fetch((HV*)SvRV(urpm), "nofatal", 7, 0);
	  if (!nofatal || !SvIV(*nofatal))
	      croak("cannot open hdlist file %s", filename);
      }
    } else croak("first argument should contain a depslist ARRAY reference");
  } else croak("first argument should be a reference to a HASH");

void
Urpm_parse_rpm(urpm, filename, ...)
  SV *urpm
  char *filename
  PPCODE:
  if (SvROK(urpm) && SvTYPE(SvRV(urpm)) == SVt_PVHV) {
    SV **fdepslist = hv_fetch((HV*)SvRV(urpm), "depslist", 8, 0);
    AV *depslist = fdepslist && SvROK(*fdepslist) && SvTYPE(SvRV(*fdepslist)) == SVt_PVAV ? (AV*)SvRV(*fdepslist) : NULL;
    SV **fprovides = hv_fetch((HV*)SvRV(urpm), "provides", 8, 0);
    HV *provides = fprovides && SvROK(*fprovides) && SvTYPE(SvRV(*fprovides)) == SVt_PVHV ? (HV*)SvRV(*fprovides) : NULL;

    if (depslist != NULL) {
      struct s_Package pkg, *_pkg;
      SV *sv_pkg;
      int packing = 0;
      int keep_all_tags = 0;
      SV *callback = NULL;
      rpmVSFlags vsflags = RPMVSF_DEFAULT;

      /* compability mode with older interface of parse_hdlist */
      if (items == 3) {
	packing = SvIV(ST(2));
      } else if (items > 3) {
	int i;
	for (i = 2; i < items-1; i+=2) {
	  STRLEN len;
	  char *s = SvPV(ST(i), len);

	  if (len == 7 && !memcmp(s, "packing", 7)) {
	    packing = SvIV(ST(i + 1));
	  } else if (len == 13 && !memcmp(s, "keep_all_tags", 13)) {
	    keep_all_tags = SvIV(ST(i+1));
	  } else if (len == 8 && !memcmp(s, "callback", 8)) {
	    if (SvROK(ST(i+1))) callback = ST(i+1);
	  } else if (len == 5) {
            if (!memcmp(s, "nopgp", 5)) {
              if (SvIV(ST(i+1))) vsflags |= (RPMVSF_NOSHA1 | RPMVSF_NOSHA1HEADER);
            }
            else if (!memcmp(s, "nogpg", 5)) {
              if (SvIV(ST(i+1))) vsflags |= (RPMVSF_NOSHA1 | RPMVSF_NOSHA1HEADER);
            }
            else if (!memcmp(s, "nomd5", 5)) {
              if (SvIV(ST(i+1))) vsflags |= (RPMVSF_NOMD5 |  RPMVSF_NOMD5HEADER);
            }
            else if (!memcmp(s, "norsa", 5)) {
              if (SvIV(ST(i+1))) vsflags |= (RPMVSF_NORSA | RPMVSF_NORSAHEADER);
            }
            else if (!memcmp(s, "nodsa", 5)) {
              if (SvIV(ST(i+1))) vsflags |= (RPMVSF_NODSA | RPMVSF_NODSAHEADER);
            }
          } else if (len == 9) {
            if (!memcmp(s, "nodigests", 9)) {
              if (SvIV(ST(i+1))) vsflags |= _RPMVSF_NODIGESTS;
            } else
            if (!memcmp(s, "nopayload", 9)) {
              if (SvIV(ST(i+1))) vsflags |= _RPMVSF_NOPAYLOAD;
            }
          } 
	}
      }
      PUTBACK;
      memset(&pkg, 0, sizeof(struct s_Package));
      pkg.flag = 1 + av_len(depslist);
      _pkg = memcpy(malloc(sizeof(struct s_Package)), &pkg, sizeof(struct s_Package));

      if (update_header(filename, _pkg, keep_all_tags, vsflags)) {
	sv_pkg = sv_setref_pv(newSVpv("", 0), "URPM::Package", _pkg);
	if (call_package_callback(urpm, sv_pkg, callback)) {
	  if (provides) {
	    update_provides(_pkg, provides);
	    update_provides_files(_pkg, provides);
	  }
	  if (packing) pack_header(_pkg);
	  av_push(depslist, sv_pkg);
	}
	SPAGAIN;
	/* only one element read */
	XPUSHs(sv_2mortal(newSViv(av_len(depslist))));
	XPUSHs(sv_2mortal(newSViv(av_len(depslist))));
      } else free(_pkg);
    } else croak("first argument should contain a depslist ARRAY reference");
  } else croak("first argument should be a reference to a HASH");

char *
Urpm_verify_rpm(filename, ...)
  char *filename
  PREINIT:
  rpmVSFlags vsflags = RPMVSF_DEFAULT;
  rpmVSFlags oldvsflags = RPMVSF_DEFAULT;
  URPM__DB db = NULL;
  Header ret = NULL;
  rpmRC rc = 0;
  FD_t fd;
  int i;
  char * fmtsig = NULL;
  char buffer[8192];
  rpmts ts;
  CODE:
  for (i = 1; i < items-1; i+=2) {
    STRLEN len;
    char *s = SvPV(ST(i), len);

    if (len == 2 && !memcmp(s, "db", 2)) {
      if (sv_derived_from(ST(i+1), "URPM::DB")) {
	IV tmp = SvIV((SV*)SvRV(ST(i+1)));
	db = INT2PTR(URPM__DB, tmp);
      } else
	croak("db is not of type URPM::DB");
    } else if (len == 5) {
      if (!memcmp(s, "nopgp", 5)) {
	if (SvIV(ST(i+1))) vsflags |= (RPMVSF_NOSHA1 | RPMVSF_NOSHA1HEADER);
      }
      else if (!memcmp(s, "nogpg", 5)) {
	if (SvIV(ST(i+1))) vsflags |= (RPMVSF_NOSHA1 | RPMVSF_NOSHA1HEADER);
      }
      else if (!memcmp(s, "nomd5", 5)) {
        if (SvIV(ST(i+1))) vsflags |= (RPMVSF_NOMD5 |  RPMVSF_NOMD5HEADER);
      }
      else if (!memcmp(s, "norsa", 5)) {
        if (SvIV(ST(i+1))) vsflags |= (RPMVSF_NORSA | RPMVSF_NORSAHEADER);
      }
      else if (!memcmp(s, "nodsa", 5)) {
        if (SvIV(ST(i+1))) vsflags |= (RPMVSF_NODSA | RPMVSF_NODSAHEADER);
      }
    }
    else if (len == 9 && !memcmp(s, "nodigests", 9)) {
      if (SvIV(ST(i+1))) vsflags |= _RPMVSF_NODIGESTS;
    }
    else if (len == 12 && !memcmp(s, "nosignatures", 12)) {
      vsflags |= _RPMVSF_NOSIGNATURES;
    }
  }
  RETVAL = NULL;
  fd = fdOpen(filename, O_RDONLY, 0);
  if (fdFileno(fd) < 0) {
    RETVAL = "Couldn't open file";
  } else {
    if (db) {
      ts = db->ts;
      /* setting verify flags, keeping trace of current flags */
      oldvsflags = rpmtsSetVSFlags(ts, vsflags);
    } else {
      /* compabilty mode to use rpmdb installed on / */
      ts = rpmtsCreate();
      read_config_files(0);
      rpmtsSetRootDir(ts, "/");
      rpmtsOpenDB(ts, O_RDONLY);
    }

    rc = rpmReadPackageFile(ts, fd, filename, &ret);
    fdClose(fd);

    if (ret) {
      fmtsig = headerSprintf(
          ret,
          "%|DSAHEADER?{%{DSAHEADER:pgpsig}}:{%|RSAHEADER?{%{RSAHEADER:pgpsig}}:"
          "{%|SIGGPG?{%{SIGGPG:pgpsig}}:{%|SIGPGP?{%{SIGPGP:pgpsig}}:{(none)}|}|}|}|",
          rpmTagTable, rpmHeaderFormats, NULL);
      headerFree(ret);
      switch(rc) {
        case RPMRC_OK:
          sprintf(buffer, "%s", fmtsig);
          RETVAL = buffer;
        break;
        case RPMRC_NOTFOUND:
          sprintf(buffer, "%s (missing key) NOT OK", fmtsig);
          RETVAL = buffer;
        break;
        case RPMRC_FAIL:
          RETVAL = "(can't get key) NOT OK";
        break;
        case RPMRC_NOTTRUSTED:
          sprintf(buffer, "%s (Key not trusted) OK", fmtsig);
          RETVAL = buffer;
        break;
        case RPMRC_NOKEY:
          sprintf(buffer, "(no key found) OK");
          RETVAL = buffer;
        break;
        default: /* can't happen */
        break;
      }
    } else {
	RETVAL = "Unable to read rpm file";
    }
  }

  if (!db)
    ts = rpmtsFree(ts);
  else
    /* Restoring verification flag to the ts */
    (void) rpmtsSetVSFlags(ts, oldvsflags);

  _free(fmtsig);
  if (!RETVAL) RETVAL = "";
  OUTPUT:
  RETVAL

int
Urpm_import_pubkey(...)
  PREINIT:
  int i;
  URPM__DB db = NULL;
  char *root = "/";
  STRLEN block_len = 0;
  char *block = NULL;
  STRLEN filename_len = 0;
  char *filename = NULL;
  rpmts ts;
  const unsigned char *pkt = NULL;
  ssize_t pktlen = 0;
  const byte * b = NULL;
  ssize_t blen;
  int rc;
  CODE:
  for (i = 0; i < items-1; i+=2) {
    STRLEN len;
    char *s = SvPV(ST(i), len);

    if (len == 2 && !memcmp(s, "db", 2)) {
      if (sv_derived_from(ST(i+1), "URPM::DB")) {
	IV tmp = SvIV((SV*)SvRV(ST(i+1)));
	db = INT2PTR(URPM__DB, tmp);
      }
    } else if (len == 4) {
      if (!memcmp(s, "root", 4))
	root = SvPV_nolen(ST(i+1));
    } else if (len == 5) {
      if (!memcmp(s, "block", 5))
	block = SvPV(ST(i+1), block_len);
    } else if (len == 8) {
      if (!memcmp(s, "filename", 8))
	filename = SvPV(ST(i+1), filename_len);
    }
  }
  RETVAL = 1;
  /* get transaction for importing keys, open rpmdb in write mode */
  if (db) {
    ts = db->ts;
  } else {
    /* compabilty mode to use rpmdb installed on / */
    ts = rpmtsCreate();
    read_config_files(0);
    rpmtsSetRootDir(ts, root);
    rpmtsOpenDB(ts, O_RDWR | O_CREAT);
  }
  rpmtsClean(ts);
  /* from pgpReadPkts the filename should be slurped directly in memory */
  if (filename) {
    rc = rpmioSlurp(filename, &b, &blen);
  } else if (block) {
    blen = block_len;
    b = memcpy(malloc(blen+1), block, blen+1); /* XXX should use xmalloc instead */
    rc = 0;
  }
  if (rc || b == NULL || blen <= 0) {
    /* error reading file, or no file or block */
    RETVAL = 0;
  } else {
    /* from pgpReadPkts the remaining of method */
    const char * enc = NULL;
    const char * crcenc = NULL;
    byte * dec;
    byte * crcdec;
    size_t declen;
    size_t crclen;
    u_int32_t crcpkt, crc;
    const char * armortype = NULL;
    char * t, * te;
    int pstate = 0;
    int _rc;

    rc = PGPARMOR_ERROR;	/* XXX assume failure */

    if (pgpIsPkt(b)) {
#ifdef NOTYET	/* XXX ASCII Pubkeys only, please. */
	rc = 0;	/* XXX fish out pkt type. */
#endif
	goto exit;
    }
#define	TOKEQ(_s, _tok)	(!strncmp((_s), (_tok), sizeof(_tok)-1))
    for (t = (char *)b; t && *t; t = te) {
	if ((te = strchr(t, '\n')) == NULL)
	    te = t + strlen(t);
	else
	    te++;

	switch (pstate) {
	case 0:
	    armortype = NULL;
	    if (!TOKEQ(t, "-----BEGIN PGP "))
		continue;
	    t += sizeof("-----BEGIN PGP ")-1;

	    _rc = pgpValTok(pgpArmorTbl, t, te);
	    if (_rc < 0)
		goto exit;
	    if (_rc != PGPARMOR_PUBKEY)	/* XXX ASCII Pubkeys only, please. */
		continue;
	    armortype = t;

	    t = te - (sizeof("-----\n")-1);
	    if (!TOKEQ(t, "-----\n"))
		continue;
	    *t = '\0';
	    pstate++;
	    /*@switchbreak@*/ break;
	case 1:
	    enc = NULL;
	    _rc = pgpValTok(pgpArmorKeyTbl, t, te);
	    if (_rc >= 0)
		continue;
	    if (*t != '\n') {
		pstate = 0;
		continue;
	    }
	    enc = te;		/* Start of encoded packets */
	    pstate++;
	    /*@switchbreak@*/ break;
	case 2:
	    crcenc = NULL;
	    if (*t != '=')
		continue;
	    *t++ = '\0';	/* Terminate encoded packets */
	    crcenc = t;		/* Start of encoded crc */
	    pstate++;
	    /*@switchbreak@*/ break;
	case 3:
	    pstate = 0;
	    if (!TOKEQ(t, "-----END PGP "))
		goto exit;
	    *t = '\0';		/* Terminate encoded crc */
	    t += sizeof("-----END PGP ")-1;

	    if (armortype == NULL) /* XXX can't happen */
		continue;
	    _rc = strncmp(t, armortype, strlen(armortype));
	    if (_rc)
		continue;

	    t = te - (sizeof("-----\n")-1);
	    if (!TOKEQ(t, "-----\n"))
		goto exit;

	    if (b64decode(crcenc, (void **)&crcdec, &crclen) != 0)
		continue;
	    crcpkt = pgpGrab(crcdec, crclen);
	    crcdec = _free(crcdec);
	    if (b64decode(enc, (void **)&dec, &declen) != 0)
		goto exit;
	    crc = pgpCRC(dec, declen);
	    if (crcpkt != crc)
		goto exit;
	    b = _free(b);
	    b = dec;
	    blen = declen;
	    rc = PGPARMOR_PUBKEY;	/* XXX ASCII Pubkeys only, please. */
	    goto exit;
	    /*@notreached@*/ /*@switchbreak@*/ break;
	}
    }
    rc = PGPARMOR_NONE;

    exit:
    if (rc > PGPARMOR_NONE)
	pkt = b;
    else if (b != NULL)
	b = _free(b);
    pktlen = blen;
  }
  if (rc < 0) {
    /* import read failed */
    RETVAL = 0;
  } else if (rc != PGPARMOR_PUBKEY) {
    /* not armored public key */
    RETVAL = 0;
  } else if ((rc = rpmcliImportPubkey(ts, pkt, pktlen)) != 0) {
    /* import failed */
    RETVAL = 0;
  }
  rpmtsClean(ts);
  _free(pkt);
  if (!db) rpmtsFree(ts);
  OUTPUT:
  RETVAL

void
Urpm_stream2header(fp)
    FILE *fp
  PREINIT:
    FD_t fd;
    URPM__Package pkg;
  PPCODE:
    if ((fd = fdDup(fileno(fp)))) {
	pkg = (URPM__Package)malloc(sizeof(struct s_Package));
	memset(pkg, 0, sizeof(struct s_Package));
        pkg->h = headerRead(fd, HEADER_MAGIC_YES);
        if (pkg->h) {
            SV *sv_pkg;
            EXTEND(SP, 1);
            sv_pkg = sv_newmortal();
            sv_setref_pv(sv_pkg, "URPM::Package", (void*)pkg);
            PUSHs(sv_pkg);
        }
        Fclose(fd);
    }

void
Urpm_spec2srcheader(specfile)
  char *specfile
  PREINIT:
    rpmts ts = rpmtsCreate();
    URPM__Package pkg;
    Spec spec = NULL;
  PPCODE:
/* Do not verify architecture */
#define SPEC_ANYARCH 1
/* Do not verify whether sources exist */
#define SPEC_FORCE 1
  if (!parseSpec(ts, specfile, "/", NULL, 0, NULL, NULL, SPEC_ANYARCH, SPEC_FORCE)) {
    int_32 one = 1;
    SV *sv_pkg;
    spec = rpmtsSetSpec(ts, NULL);
    if (! spec->sourceHeader)
      initSourceHeader(spec);
    pkg = (URPM__Package)malloc(sizeof(struct s_Package));
    memset(pkg, 0, sizeof(struct s_Package));
    headerAddEntry(spec->sourceHeader, RPMTAG_SOURCEPACKAGE, RPM_INT32_TYPE, &one, 1);
    pkg->h = headerLink(spec->sourceHeader);
    sv_pkg = sv_newmortal();
    sv_setref_pv(sv_pkg, "URPM::Package", (void*)pkg);
    XPUSHs(sv_pkg);
    spec = freeSpec(spec);
  } else {
    XPUSHs(&PL_sv_undef);
    /* apparently rpmlib sets errno this when given a bad spec. */
    if (errno == EBADF)
      errno = 0;
  }
  ts = rpmtsFree(ts);

void
expand(name)
    char * name
    PPCODE:
    const char * value = rpmExpand(name, NULL);
    XPUSHs(sv_2mortal(newSVpv(value, 0)));

void
add_macro_noexpand(macro)
    char * macro
    CODE:
    rpmDefineMacro(NULL, macro, RMIL_DEFAULT);

void
del_macro(name)
    char * name
    CODE:
    delMacro(NULL, name);

void
loadmacrosfile(filename)
    char * filename
    PPCODE:
    rpmInitMacros(NULL, filename);

void
resetmacros()
    PPCODE:
    rpmFreeMacros(NULL);

void
setVerbosity(level)
    int level
    PPCODE:
    rpmSetVerbosity(level);

const char *
rpmErrorString()

void
rpmErrorWriteTo(fd)
  int fd
  CODE:
  rpmError_callback_data = fd;
  rpmErrorSetCallback(rpmError_callback);

  /* vim:set ts=8 sts=2 sw=2: */
