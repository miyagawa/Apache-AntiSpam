package Apache::AntiSpam;

use strict;
use vars qw($VERSION);
$VERSION = '0.03';

use Apache::Constants qw(:common);
use Apache::File;
use Email::Find 0.04;

sub handler {
    my $r = shift;

    my $filtered = uc($r->dir_config('Filter')) eq 'ON';

    # makes Apache::Filter aware
    # snippets stolen from Geoffrey Young's Apache::Clean 
    $r = $r->filter_register if $filtered;

    # AntiSpam filtering is done on text/* files
    return DECLINED unless ($r->content_type =~ m,^text/, && $r->is_main);
    
    my($fh, $status);
    if ($filtered) {
	($fh, $status) = $r->filter_input;
	undef $fh unless $status == OK;
    } else {
	$fh = Apache::File->new($r->filename);
    }

    return DECLINED unless $fh;
    
    # finds and replaces e-mail addresses
    # if-statement should be outside the sub for efficiency
    my $replacer;
    if (uc($r->dir_config('AntiSpamFormat')) eq 'SPACES') {
	$replacer = sub {
	    my($email, $orig) = @_;
	    $orig =~ s/\@/ at /g;
	    $orig =~ s/\./ dot /g;
	    $orig =~ s/\-/ bar /g;
	    $orig =~ s/  */ /g;
	    return $orig;
	};
    } else {
	$replacer = sub {
	    my($email, $orig) = @_;
	    $orig =~ s/\@/-nospam\@/;
	    return $orig;
	};
    }

    $r->send_http_header;

    local $/;		# slurp
    my $input = <$fh>;
    find_emails($input, \&$replacer);
    $r->print($input);

    return OK;
}    

1;
__END__

=head1 NAME

Apache::AntiSpam - AntiSpam filter for web pages

=head1 SYNOPSIS

  # in httpd.conf
  <Location /antispam>
  SetHandler perl-script
  PerlHandler Apache::AntiSpam
  </Location>

  # off course, filter aware!
  PerlModule Apache::Filter
  SetHandler perl-script
  PerlSetVar Filter On
  PerlHandler Apache::RegistryFilter Apache::AntiSpam Apache::Compress

=head1 DESCRIPTION

Apache::AntiSpam is a filter module to prevent e-mail addresses
exposed as is on web pages. This module replaces e-mail addresses in
web pages with one of the formats listed below. (you can choose one)

=over 4

=item *

miyagawa-nospam@cpan.org

=item *

miyagawa at cpan dot org

=back

This module is Filter aware, meaning that it can work within
Apache::Filter framework without modification.

=head1 CONFIGURATION

  # choose either of two
  PerlSetVar AntiSpamFormat NoSpam
  PerlSetVar AntiSpamFormat Spaces

C<AntiSpamFormat> indicates the way Apache::AntiSpam replaces the
e-mail addresses.

=over 4

=item C<NoSpam>

replaces B<miyagawa@cpan.org> with B<miyagawa-nospam@cpan.org>. (default)

=item C<Spaces>

replaces B<miyagawa@cpan.org> with B<miyagawa at cpan dot org>.

=back

=head1 TODO

=over 4

=item *

B<-nospam> suffix should be configured (easy).

=item *

More logging with Apache::Log.

=item *

remove mailto: tags using HTML::Parser.

=item *

Make it easy to subclass so that the antispamming method can be configured.

=back

=head1 ACKNOWLEDGEMENTS

The idea of this module is stolen from Apache::AddrMunge by Mark J
Dominus.  See http://perl.plover.com/AddrMunge/ for details.

Many thanks to Michael G. Schwern for kindly improving the matching
speed of Email::Find.

=head1 AUTHOR

Tatsuhiko Miyagawa <miyagawa@bulknews.net>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

L<Email::Find>, L<Apache::Filter>

=cut
