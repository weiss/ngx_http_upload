upload.pm
=========

This [Nginx][1] module implements the HTTP server's part of the XMPP extension
[XEP-0363: HTTP File Upload][2]. It can be used with either ejabberd's
[`mod_http_upload`][3] or Prosody's [`mod_http_upload_external`][4].

Nginx setup
-----------

1. Create a directory and move `upload.pm` into it, e.g.:

    ```sh
    # mkdir -p /usr/local/lib/perl
    # wget -P /usr/local/lib/perl https://git.io/fNZgL
    ```

2. Install the [`ngx_http_perl_module`][5]. On Debian/Ubuntu-based
   distributions, the package is called `libnginx-mod-http-perl`, on
   RedHat/CentOS-based distributions, it's `nginx-mod-http-perl`.

3. Add the following snippets to the appropriate sections of your Nginx
   configuration:

    ```nginx configuration file
    # This directive was probably added by the distribution package already:
    load_module modules/ngx_http_perl_module.so;

    http {
        # Add the following two lines to the existing "http" block.
        perl_modules /usr/local/lib/perl; # Path to upload.pm.
        perl_require upload.pm;
    }

    server {
        # Specify directives such as "listen", "server_name", and TLS-related
        # settings for the "server" that handles the uploads.

        # Uploaded files will be stored below the "root" directory. To minimize
        # disk I/O, make sure the specified path is on the same file system as
        # the directory used by Nginx to store temporary files holding request
        # bodies ("client_body_temp_path", often some directory below /var).
        root /var/www/upload;

        # Specify this "location" block (if you don't use "/", see below):
        location / {
            perl upload::handle;
        }

        # Upload file size limit (default: 1m), also specified in your XMPP
        # server's upload module configuration (see below):
        client_max_body_size 100m;
    }
    ```

4. Open `upload.pm` in an editor and adjust the configuration at the top of the
   file:

   - The `$external_secret` must match the one specified in your XMPP server's
     upload module configuration (see below).

   - If the root path of the upload URIs (the `location` specified in the Nginx
     `server` block) isn't `/` but `/some/prefix/`, `$uri_prefix_components`
     must be set to the number of directory levels. So, for `/some/prefix/`, it
     would be `2`.

ejabberd setup
--------------

Let the [`mod_http_upload`][3] option `put_url` point to Nginx, and specify
exactly the same `external_secret` as in the `upload.pm` settings:

```yaml
modules:
  mod_http_upload:
    put_url: "https://upload.example.com"
    external_secret: "it-is-secret"
    max_size: 104857600 # 100 MiB, also specified in the Nginx configuration.
```

Prosody setup
-------------

Let the [`mod_http_upload_external`][4] option `http_upload_external_base_url`
point to Nginx, and specify exactly the same `http_upload_external_secret` as in
the `upload.pm` settings:

```lua
http_upload_external_base_url = "https://upload.example.com"
http_upload_external_secret = "it-is-secret"
http_upload_external_file_size_limit = 104857600 -- 100 MiB
```

Contact
-------

If you have any questions, you could ask in the ejabberd room:
`ejabberd@conference.process-one.net` (the maintainer of this module is usually
joined as _Holger_).

[1]: https://nginx.org/en/
[2]: https://xmpp.org/extensions/xep-0363.html
[3]: https://docs.ejabberd.im/admin/configuration/#mod-http-upload
[4]: https://modules.prosody.im/mod_http_upload_external.html#implementation
[5]: https://nginx.org/en/docs/http/ngx_http_perl_module.html
