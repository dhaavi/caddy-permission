# Caddy Permission Plugin

This plugin allows the user to provide generic authentication and authorization based on HTTP methods. It's main use case is to add (SSO) authentication and authorization to unsupported web services.

## Usage

The Permission plugin works by filtering HTTP methods and request paths. The most common methods are included in the shortcuts _readonly_ `ro`, _read/write_ `rw`, _websockets_ `ws`, _any_ and _none_:

- `ro`: GET, HEAD, PROPFIND, OPTIONS, LOCK, UNLOCK
- `rw`: GET, HEAD, PROPFIND, OPTIONS, LOCK, UNLOCK, POST, PUT, DELETE, MKCOL, PROPPATCH
- `ws`: WEBSOCKET
- `any`: _any_ (may not be combined)
- `none`: _none_ (may not be combined)

If you want to specify your methods yourself, be sure to not have any spaces between them: `GET,HEAD,...`. If you prepend the list of methods with `~`, you can _invert_ their meaning, effectively turning the whitelist into a blacklist. The Permission plugin works on a prefix basis. Every path provided matches the exact path _and_ every path that starts with the provided path. Be very careful with using the `none` option, the rules are already in a whitelist mode, you will not use this often. Please refer to the _Combining Backends_ chapter to learn in which order rules are evaluated.

__Important Note: The Permission plugin is only secure if you can verify if the application you want to protect is compatible,__ meaning that it must conform to these standard HTTP methods to interact with the web service. Also, it can only deny websocket connections, but __cannot__ filter within them. You should always treat websocket connections as a full write access action.

##### Special Handling

The HTTP Methods `MOVE`, `COPY` and `PATCH` are handled a bit more special:

- `MOVE`: source path is treated as `DELETE` and destination path as `PUT`
- `COPY`: source path is treated as `GET` and destination path as `PUT`
- `PATCH`:
  - If a the `Destination` Header is present:
    - If `Action` Header is `copy`: source path is treated as `GET` and destination path as `PUT`
    - If `Action` Header is not `copy`: source path is treated as `DELETE` and destination path as `PUT`
  - If no `Destination` Header is present: treat as `PATCH`

## Backends

The different backends may be combined - They are handled in order of declaration in the Caddyfile.

Check out the test directory and play around with the different backends to get a feel for it.

Currently, three different backends are supported:
- HTTP BasicAuth (authentation & authorization)
- TLS client authentication (authentation only)
- API (authentation & authorization)

### HTTP Basic Auth

    permission basic {
      user greg qwerty1 # This is greg, his password is qwerty1
      rw /tmp/ # he may read and write to /tmp/!

      user george # This is george, he does not have a password, another backend will have to authenticate him
      rw /admin/

      default # applies to all logged-in users
      rw /api/users/0 #

      public # applies to everyone, also anonymous users
      none /internal/ # deny internal space for everyone
      ro / # allow reading everything

      GET,HEAD /other
    }

### TLS Auth

This plugin requires TLS client authentication. It simply sets the CN to the username. You can use the `HTTP Basic Auth` and/or `API Auth` plugins for handling permissions.

    permission tls


    ### API Auth

    This is a custom API, that you can implement in your existing system - it's extremely simple. Here is how you would configure it within caddy:

        permission api {
          name MyWebsite # name of website
          user http://localhost:8080/caddyapi # main authentication api
          permit http://localhost:8080/caddyapi/{{username}} # refetch a permit of a user
          login http://localhost:8080/login?next={{resource}} # redirect here for logging in (resource is original URL)
          add_prefix /api/resource /files # add prefixes to returned paths
          add_without_prefix # if add_prefix is used, but you still want to also add the original paths
          cache 600 # how to long to cache authenticated users
          cleanup 3600 # when to clean out authenticated users
        }

    __`user` Endpoint:__

    The Permission plugin creates a request user authentication at the configured URL with:

    - The original `Host` Header.
    - The originating IP in the `X-Real-IP` Header.
    - The originating IP in the `X-Forwarded-For` Header.
    - The original protocol (`http` or `https`) in the `X-Forwarded-For` Header.
    - The original BasicAuth credentials, if present.
    - All cookies.

    It expects a JSON Object in return with the following fields:

        {
          "BasicAuth":   false,
          "Cookie":      "cookieName=cookieValue",
          "Username":    "username",
          "Permissions": {}
        }

    `BasicAuth` or `Cookie` are used to declare how to identify this user in the future. Either set `BasicAuth` to true, or set `Cookie` to the authenticating cookie.

    Example:

        {
          "BasicAuth":   false,
          "Cookie":      "PHPSESSID=12345",
          "Username":    "tom",
          "Permissions": {
            "/tmp/": "rw",
            "/static": "ro",
            "/other": "GET,HEAD"
          }
        }

    __`permit` Endpoint:__

    Works very similar to the `user` endpoint, but instead of forwarding all these headers and cookies, the username is replaced in the URL.

    __`login` Endpoint:__

    If current permissions are insufficient to complete a request and the user is not yet authenticated, she is redirected to this URL.

## Combining Backends

Rules within a ruleset (user, default, public) are evaulated in the order they are configured.
When combining different backends, the backend defined earlier is always asked first. This is handled as follows:

- Try to authenticate the user with every backend, stop if successful.
- If authenticated:
  - Check the user's permissions and default permissions for every backend, stop if a match is found.
- Check the public permit for every backend, stop if allowed.
- Let the first backend to support login handle login.

So, for example, with the API and Basic backend the order will be:
- API user ruleset
- API default ruleset
- Basic user ruleset
- Basic default ruleset
- API public ruleset
- Basic public ruleset

## Other Options

There are also a couple other options regardless of backend:

    permission realm "Restricted Site" # sets name
    permission allow_reading_parent_paths # applies read rights to parent paths
    set_basicauth username password # set basic auth on forwarded request
    set_cookie name value # set cookie on forwarded request, may be used multiple times
