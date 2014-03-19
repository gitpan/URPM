use strict;
use ExtUtils::MakeMaker;
use List::Util 'first';
use ExtUtils::PkgConfig;

die("OS unsupported\n") if $^O ne 'linux';

my %cfg;
my $cfg_success = eval {
%cfg = ExtUtils::PkgConfig->find (
    "rpm >= 4.10");
  1;
};
if (!$cfg_success) {
  warn $@;
  exit 0;
}

my $is_debian = -f '/etc/debian_version';
my $rpmbuild_pkg = $is_debian ? "rpmbuild" : "rpm-build";
my $rpmdev_pkg   = $is_debian ? "librpm-dev" : "rpm-devel";

# where to find the rpm utility

my $rpm_path = $ENV{RPM_PATH}; # this overrides

unless (defined $rpm_path) {
    $rpm_path = first { -x $_ } qw(/bin/rpm /usr/bin/rpm);
}

defined $rpm_path or die "Can't find rpm on this system\n" .
			"Ensure $rpmdev_pkg >= 4.9 is installed";

my $rpmbuild = first { -x $_ } qw(/bin/rpmbuild /usr/bin/rpmbuild);
defined $rpmbuild or die "Can't find rpmbuild on this system\n" .
			"Ensure $rpmbuild_pkg >= 4.9 is installed";

sub hexversion {
	my ($major, $minor, $micro) = (@_[0] =~ /(\d+)\.(\d+)\.?(\d+)?/);
	return int($major<<16) + int($minor<<8) + int($micro<<0);
}

my $version = `LC_ALL=C $rpm_path --version`;
# fix compiling with RCs:
$version =~ s/(-.*)|(\.DEVEL)//;
chomp $version;
$version =~ s/(RPM version )|(rpm \(RPM\) )//;
my $hversion = hexversion($version);
$hversion ge hexversion("4.9") or die "Unable to build URPM with too old (or undetected) rpm version $version\n";

# to generate the ChangeLog depending on the checkout layout
my $commonusername = "../common/";
-d $commonusername or do {
    $commonusername = "../../common/";
    -d $commonusername or do {
	$commonusername = "../../../common/";
	-d $commonusername or $commonusername = "";
    };
};

sub MY::postamble {
    <<"**MM**";
.PHONY: ChangeLog

ChangeLog:
	LC_ALL=C svn2cl --accum --strip-prefix=soft/rpm/perl-URPM/trunk --authors ${commonusername}username.xml
	rm -f *.bak
**MM**
}

my @rpmflags;
if ($hversion ge hexversion("4.9.0") && $hversion lt hexversion("5.0")) {
    # rpm.org version 4.9.0
    push @rpmflags, "-DRPM490";
}

my $ccflags = join(' ', '-Wall -Wextra -fno-strict-aliasing', @rpmflags);

print "Found RPM version $version (compiling with flags: $ccflags)\n";

WriteMakefile(
    NAME	=> 'URPM',
    PREREQ_PM	=> {
	'MDV::Packdrakeng' => '1.00',
    },
    MIN_PERL_VERSION => '5.008001',
    META_MERGE		=> {
        q(meta-spec)          => {
            version => '2',
            url     => 'http://search.cpan.org/perldoc?CPAN::Meta::Spec',
        },
	    release_status => 'testing' },
    CCFLAGS	=> $ccflags,
    VERSION_FROM	=> 'URPM.pm',
    LIBS	=> [ $cfg{libs}, "-lrpmbuild" ],
    INC		=> '-I/usr/include/rpm',
    dist	=> { COMPRESS => "xz -f", SUFFIX => ".xz" },
    realclean	=> { FILES => "t/RPMS/noarch/*" },
);
