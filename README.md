# nginx-njs-oidc-proxy

An alternative of [oauth2_proxy](https://github.com/pusher/oauth2_proxy) implemented with [njs scripting language](http://nginx.org/en/docs/njs/).
There is a [similar implementation](https://github.com/nginxinc/nginx-openid-connect) for NGINX Plus, but this can also work on open source NGINX.

## Try It!

1. Edit `nginx/js/config.js` and fill `clientId` and `clientSecret`
	- Create *OAuth 2.0 Client ID* [here](https://console.cloud.google.com/apis/credentials)
	- Add `http://localhost/oauth2/callback` to *Authorized redirect URIs*
1. Run `docker-compose up -d`
1. Open `http://localhost/`
1. Login with your gmail account
1. It works!

## Tips

- You must set `cookieSecret` on production environment.
- You can implement custom auth-strategy, see `nginx/js/handler.js` and `nginx/js/acl.js`.
- You can pass some user profile to backend, see an end of `authHandler` function.
- Initial implementation uses Google as an OpenID provider. Other providers also can be used.
