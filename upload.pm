# See: https://modules.prosody.im/mod_http_upload_external.html
#
# Holger Weiss <holger@zedat.fu-berlin.de>, 2018.

package upload;

#### INSTALLATION

# 1) Create a directory and move this module into it, e.g., /usr/local/lib/perl.
#
# 2) Install ngx_http_perl_module (on Debian/Ubuntu: libnginx-mod-http-perl).
#
# 3) Add the following snippets to the appropriate sections of your Nginx
#    configuration (the "load_module" directive might've been added by a
#    distribution package already):
#
#    load_module modules/ngx_http_perl_module.so;
#    http {
#        # [...]
#        perl_modules /usr/local/lib/perl;
#        perl_require upload.pm;
#    }
#    server {
#        # [...]
#        location / {
#            perl upload::handle;
#        }
#    }
#
# 4) Adjust the configuration below. Notes:
#
#    - The $external_secret must match the one specified in your XMPP server's
#      upload module configuration.
#    - If the root path of the upload URIs (i.e., the "location" specified in
#      Nginx) isn't "/" but "/some/prefix/", $uri_prefix_components must be set
#      to the number of directory levels; for "/some/prefix/", it would be 2.

#### CONFIGURATION

my $external_secret = 'it-is-secret';
my $file_mode = 0640;
my $dir_mode  = 0750;
my $uri_prefix_components = 0;
my %custom_headers = (
    'Access-Control-Allow-Origin' => '*',
    'Access-Control-Allow-Methods' => 'OPTIONS, HEAD, GET, PUT',
    'Access-Control-Allow-Headers' => 'Authorization',
    'Access-Control-Allow-Credentials' => 'true',
);

#### END OF CONFIGURATION

use warnings;
use strict;
use Carp;
use Digest::SHA qw(hmac_sha256_hex);
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

    if (-r $r->filename and -f _) {
        $r->allow_ranges;
        $r->send_http_header;
        $r->sendfile($r->filename) unless $r->header_only;
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

    if ($r->args =~ /v=([[:xdigit:]]{64})/) {
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
    my $safe_uri = $r->uri =~ s|[^\p{Alnum}/_.-]|_|gr;
    my $file_path = substr($r->filename, 0, -length($r->uri)) . $safe_uri;
    my $dir_path = dirname($file_path);

    make_path($dir_path, {chmod => $dir_mode, error => \my $error});
    if (@$error) {
        $r->log_error($!, "Cannot create directory $dir_path");
        return HTTP_FORBIDDEN; # Assume EACCES.
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
            $r->log_error($!, "Cannot set binary mode for $dst_path");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (not syswrite($fh, $body)) {
            $r->log_error($!, "Cannot write $dst_path");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (not close($fh)) {
            $r->log_error($!, "Cannot close $dst_path");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    } elsif ($!{EEXIST}) {
        $r->log_error($!, "Won't overwrite $dst_path");
        return HTTP_CONFLICT;
    } elsif ($!{EACCES}) {
        $r->log_error($!, "Cannot create $dst_path");
        return HTTP_FORBIDDEN;
    } else {
        $r->log_error($!, "Cannot open $dst_path");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (chmod($mode, $dst_path) < 1) {
        $r->log_error($!, "Cannot change permissions of $dst_path");
        return HTTP_INTERNAL_SERVER_ERROR;
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
        $r->log_error($!, "Cannot move data to $dst_path");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (chmod($mode, $dst_path) < 1) {
        $r->log_error($!, "Cannot change permissions of $dst_path");
        return HTTP_INTERNAL_SERVER_ERROR;
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

sub safe_eq {
    my $a = shift;
    my $b = shift;
    my $n = length($a);
    my $r = 0;

    croak('safe_eq arguments differ in length') if length($b) != $n;
    $r |= ord(substr($a, $_)) ^ ord(substr($b, $_)) for 0 .. $n - 1;
    return $r == 0;
}

1;
__END__
