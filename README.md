# ldap

## Name

*ldap* - serves a zone from a ldap backend.

## Description

The ldap plugin resolve A, AAAA y PTR RR from ldap backend. To reduce load on the backend, you can configure `cacheTimeout=30m`.

## Compilation

This package will always be compiled as part of CoreDNS and not in a standalone way. It will require you to use `go get` or as a dependency on [plugin.cfg](https://github.com/coredns/coredns/blob/master/plugin.cfg).

The [manual](https://coredns.io/manual/toc/#what-is-coredns) will have more information about how to configure and extend the server with external plugins.

A simple way to consume this plugin, is by adding the following on [plugin.cfg](https://github.com/coredns/coredns/blob/master/plugin.cfg), and recompile it as [detailed on coredns.io](https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/#build-with-compile-time-configuration-file).

~~~
ldap:github.com/xoe-labs/ldap
~~~

After this you can compile coredns by:

```shell script
go generate
go build
```

Or you can instead use make:

```shell script
make
```

## Syntax

~~~ txt
ldap
~~~

## Metrics

If monitoring is enabled (via the *prometheus* directive) the following metric is exported:

* `coredns_ldap_request_count_total{server}` - query count to the *ldap* plugin.

The `server` label indicated which server handled the request, see the *metrics* plugin for details.

## Ready

This plugin reports readiness to the ready plugin. It will be immediately ready.

## Examples

In this configuration, we forward all queries to 9.9.9.9 and print "ldap" whenever we receive
a query.

~~~ corefile
. {
  forward . 9.9.9.9
  ldap
}
~~~

## Also See

See the [manual](https://coredns.io/manual).
