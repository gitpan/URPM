#!/usr/bin/perl

# $Id: parse.t,v 1.16 2006/03/06 13:45:25 rgarciasuarez Exp $

use strict;
use warnings;
use Test::More tests => 29;
use MDV::Packdrakeng;
use URPM;
use URPM::Build;
use URPM::Query;

# shut up
URPM::setVerbosity(2);

my $a = new URPM;
ok($a);

END { unlink 'hdlist.cz' }

my ($start, $end) = $a->parse_rpms_build_headers(rpms => [ "t/RPMS/noarch/test-rpm-1.0-1mdk.noarch.rpm" ], keep_all_tags => 1);
ok(@{$a->{depslist}} == 1);
my $pkg = $a->{depslist}[0];
ok($pkg);
my %tags = $a->list_rpm_tag;
ok(keys %tags);
is($pkg->get_tag(1000), 'test-rpm', 'name');
is($pkg->get_tag(1001), '1.0', 'version');
is($pkg->get_tag(1002), '1mdk', 'release');
TODO: {
    local $TODO = "not implemented";
    is($pkg->queryformat("%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}"), "test-rpm-1.0-1mdk.noarch",
	q/get headers from parsing rpm/);
}

$a->build_hdlist(
    start  => 0,
    end    => $#{$a->{depslist}},
    hdlist => 'hdlist.cz',
    ratio  => 9,
);

ok(-f 'hdlist.cz');

my $b = new URPM;
($start, $end) = $b->parse_hdlist('hdlist.cz', keep_all_tags => 1);
ok(@{$b->{depslist}} == 1);
$pkg = $b->{depslist}[0];
ok($pkg);
is($pkg->get_tag(1000), 'test-rpm', 'name');
is($pkg->get_tag(1001), '1.0', 'version');
is($pkg->get_tag(1002), '1mdk', 'release');
is($pkg->queryformat("%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}"), "test-rpm-1.0-1mdk.noarch",
    q/get headers from hdlist/);

# Version comparison
ok(URPM::rpmvercmp("1-1mdk",     "1-1mdk") ==  0, "Same value = 0");
ok(URPM::rpmvercmp("0:1-1mdk",   "1-1mdk") ==  -1, "Same value, epoch 0 on left = 1");
ok(URPM::rpmvercmp("1-1mdk",     "1-2mdk") == -1, "Right value win = -1");
ok(URPM::rpmvercmp("1-2mdk",     "1-1mdk") ==  1, "Left value win = 1");
ok(URPM::rpmvercmp("1:1-1mdk", "2:1-1mdk") == -1, "epoch 1 vs 2 = -1");

{
    open(my $hdfh, "zcat hdlist.cz 2>/dev/null |") or die $!;
    my $pkg = URPM::stream2header($hdfh);
    ok(defined $pkg, "Reading a header works");
    is($pkg->get_tag(1000), 'test-rpm');
    is($pkg->get_tag(1001), '1.0');
    is($pkg->get_tag(1002), '1mdk');
    is($pkg->queryformat("%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}"), "test-rpm-1.0-1mdk.noarch");
    close $hdfh;
}

{
    my $pkg = URPM::spec2srcheader("test-rpm.spec");
    ok(defined $pkg, "Parsing a spec works");
    is($pkg->get_tag(1000), 'test-rpm', 'parsed correctly');
    $pkg = URPM::spec2srcheader("doesnotexist.spec");
    ok(!defined $pkg, "non-existent spec");
    open my $f, '>', 'bad.spec' or die "Can't write bad.spec: $!\n";
    print $f "Name: foo\nVerssion: 2\n";
    close $f;
    $pkg = URPM::spec2srcheader("bad.spec");
    ok(!defined $pkg, "bad spec");
    END { unlink "bad.spec" }
}
