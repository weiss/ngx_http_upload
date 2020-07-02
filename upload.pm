# Nginx module to handle file uploads and downloads for ejabberd's
# mod_http_upload or Prosody's mod_http_upload_external.

# Copyright (c) 2018 Holger Weiss <holger@zedat.fu-berlin.de>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

package upload;

## CONFIGURATION -----------------------------------------------------

my $external_secret = 'it-is-secret';
my $uri_prefix_components = 0;
my $file_mode = 0640;
my $dir_mode  = 0750;
my %custom_headers = (
    'Access-Control-Allow-Origin' => '*',
    'Access-Control-Allow-Methods' => 'OPTIONS, HEAD, GET, PUT',
    'Access-Control-Allow-Headers' => 'Authorization, Content-Type',
    'Access-Control-Allow-Credentials' => 'true',
);

## END OF CONFIGURATION ----------------------------------------------

use warnings;
use strict;
use Carp;
use Digest::SHA qw(hmac_sha256_hex);
use Encode qw(decode :fallback_all);
use Errno qw(:POSIX);
use Fcntl;
use File::Copy;
use File::Basename;
use File::Path qw(make_path);
use nginx;

sub handle {
    my $r = shift;

    add_custom_headers($r);

    if ($r->request_method eq 'GET' or $r->request_method eq 'HEAD') {
        return handle_get_or_head($r);
    } elsif ($r->request_method eq 'PUT') {
        return handle_put($r);
    } elsif ($r->request_method eq 'OPTIONS') {
        return handle_options($r);
    } else {
        return DECLINED;
    }
}

sub handle_get_or_head {
    my $r = shift;
    my $file_path = safe_filename($r);

    if (-r $file_path and -f _) {
        $r->header_out('Content-Length', -s _);
        $r->allow_ranges;
        $r->send_http_header;
        $r->sendfile($file_path) unless $r->header_only;
        return OK;
    } else {
        return DECLINED;
    }
}

sub handle_put {
    my $r = shift;
    my $len = $r->header_in('Content-Length') or return HTTP_LENGTH_REQUIRED;
    my $uri = $r->uri =~ s|(?:/[^/]+){$uri_prefix_components}/||r;
    my $provided_hmac;

    if (defined($r->args) and $r->args =~ /v=([[:xdigit:]]{64})/) {
        $provided_hmac = $1;
    } else {
        $r->log_error(0, 'Rejecting upload: No auth token provided');
        return HTTP_FORBIDDEN;
    }

    my $expected_hmac = hmac_sha256_hex("$uri $len", $external_secret);

    if (not safe_eq(lc($provided_hmac), lc($expected_hmac))) {
        $r->log_error(0, 'Rejecting upload: Invalid auth token');
        return HTTP_FORBIDDEN;
    }
    if (not $r->has_request_body(\&handle_put_body)) {
        $r->log_error(0, 'Rejecting upload: No data provided');
        return HTTP_BAD_REQUEST;
    }
    return OK;
}

sub handle_put_body {
    my $r = shift;
    my $file_path = safe_filename($r);
    my $dir_path = dirname($file_path);

    make_path($dir_path, {chmod => $dir_mode, error => \my $error});
    if (@$error) {
        return system_error($r, "Cannot create directory $dir_path");
    }

    my $body = $r->request_body;
    my $body_file = $r->request_body_file;

    if ($body) {
        return store_body_from_buffer($r, $body, $file_path, $file_mode);
    } elsif ($body_file) {
        return store_body_from_file($r, $body_file, $file_path, $file_mode);
    } else { # Huh?
        $r->log_error(0, "Got no data to write to $file_path");
        return HTTP_BAD_REQUEST;
    }
}

sub store_body_from_buffer {
    my ($r, $body, $dst_path, $mode) = @_;

    if (sysopen(my $fh, $dst_path, O_WRONLY|O_CREAT|O_EXCL, $mode)) {
        if (not binmode($fh)) {
            return system_error($r, "Cannot set binary mode for $dst_path");
        }
        if (not syswrite($fh, $body)) {
            return system_error($r, "Cannot write $dst_path");
        }
        if (not close($fh)) {
            return system_error($r, "Cannot close $dst_path");
        }
    } else {
        return system_error($r, "Cannot create $dst_path");
    }
    if (chmod($mode, $dst_path) != 1) {
        return system_error($r, "Cannot change permissions of $dst_path");
    }
    return HTTP_CREATED;
}

sub store_body_from_file {
    my ($r, $src_path, $dst_path, $mode) = @_;

    # We could merge this with the store_body_from_buffer() code by handing over
    # the file handle created by sysopen() as the second argument to move(), but
    # we want to let move() use rename() if possible.

    if (-e $dst_path) {
        $r->log_error(0, "Won't overwrite $dst_path");
        return HTTP_CONFLICT;
    }
    if (not move($src_path, $dst_path)) {
        return system_error($r, "Cannot move data to $dst_path");
    }
    if (chmod($mode, $dst_path) != 1) {
        return system_error($r, "Cannot change permissions of $dst_path");
    }
    return HTTP_CREATED;
}

sub handle_options {
    my $r = shift;

    $r->header_out('Allow', 'OPTIONS, HEAD, GET, PUT');
    $r->send_http_header;
    return OK;
}

sub add_custom_headers {
    my $r = shift;

    while (my ($field, $value) = each(%custom_headers)) {
        $r->header_out($field, $value);
    }
}

sub safe_filename {
    my $r = shift;
    my $filename = decode('UTF-8', $r->filename, FB_DEFAULT | LEAVE_SRC);
    my $uri = decode('UTF-8', $r->uri, FB_DEFAULT | LEAVE_SRC);
    my $safe_uri = $uri =~ s|[^\p{Alnum}/_.-]|_|gr;

    return substr($filename, 0, -length($uri)) . $safe_uri;
}

sub safe_eq {
    my $a = shift;
    my $b = shift;
    my $n = length($a);
    my $r = 0;

    croak('safe_eq arguments differ in length') if length($b) != $n;
    $r |= ord(substr($a, $_)) ^ ord(substr($b, $_)) for 0 .. $n - 1;
    return $r == 0;
}

sub system_error {
    my ($r, $msg) = @_;

    $r->log_error($!, $msg);

    return HTTP_FORBIDDEN if $!{EACCES};
    return HTTP_CONFLICT if $!{EEXIST};
    return HTTP_INTERNAL_SERVER_ERROR;
}

1;
__END__
