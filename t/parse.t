#!/usr/bin/perl

# $Id: parse.t,v 1.12 2005/10/28 14:10:21 rgarciasuarez Exp $

use strict;
use warnings;
use Test::More tests => 24;
use MDV::Packdrakeng;
use URPM;
use URPM::Build;
use URPM::Query;

my $a = new URPM;
ok($a);

END { unlink 'hdlist.cz' }

my ($start, $end) = $a->parse_rpms_build_headers(rpms => [ "t/RPMS/noarch/test-rpm-1.0-1mdk.noarch.rpm" ], keep_all_tags => 1);
ok(@{$a->{depslist}} == 1);
my $pkg = $a->{depslist}[0];
ok($pkg);
my %tags = $a->list_rpm_tag;
ok(keys %tags);
ok($pkg->get_tag(1000) eq 'test-rpm');
ok($pkg->get_tag(1001) eq '1.0');
ok($pkg->get_tag(1002) eq '1mdk');
# ok($pkg->queryformat("%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}") eq "test-rpm-1.0-1mdk.noarch");

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
ok($pkg->get_tag(1000) eq 'test-rpm');
ok($pkg->get_tag(1001) eq '1.0');
ok($pkg->get_tag(1002) eq '1mdk');
ok($pkg->queryformat("%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}") eq "test-rpm-1.0-1mdk.noarch");

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
    ok($pkg->get_tag(1000) eq 'test-rpm');
    ok($pkg->get_tag(1001) eq '1.0');
    ok($pkg->get_tag(1002) eq '1mdk');
    ok($pkg->queryformat("%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}") eq "test-rpm-1.0-1mdk.noarch");
    close $hdfh;
}
