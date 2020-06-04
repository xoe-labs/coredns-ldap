package ldap

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/parse"
	"github.com/coredns/coredns/plugin/pkg/upstream"

	"github.com/caddyserver/caddy"
)

const pluginName = "ldap"

// Define log to be a logger with the plugin name in it.
var log = clog.NewWithPlugin(pluginName)

// init registers this plugin.
func init() { plugin.Register(pluginName, setup) }

// setup is the function that gets called when the config parser see the token "ldap". Setup is responsible
// for parsing any extra options the ldap plugin may have. The first token this function sees is "ldap".
func setup(c *caddy.Controller) error {

	// parse corefile config
	l, err := ldapParse(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	err = l.InitLdapCache(context.Background())
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	l.RegisterLdapCache(c)

	// add prometheus metrics on startup
	c.OnStartup(func() error {
		// add plugin-global metric once
		once.Do(func() {
			metrics.MustRegister(c, requestCount)
		})
		return nil
	})

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		l.Next = next
		return l
	})

	return nil
}

var once sync.Once

// RegisterLdapCache registers LdapCache start and stop functions with Caddy
func (l *Ldap) RegisterLdapCache(c *caddy.Controller) {
	c.OnStartup(func() error {
		go l.APIConn.Run()

		timeout := time.After(5 * time.Second)
		ticker := time.NewTicker(100 * time.Millisecond)
		for {
			select {
			case <-ticker.C:
				if k.APIConn.HasSynced() {
					return nil
				}
			case <-timeout:
				return nil
			}
		}
	})

	c.OnShutdown(func() error {
		return l.APIConn.Stop()
	})
}

func ldapParse(c *caddy.Controller) (*Ldap, error) {
	var (
		ldap *Ldap
		err  error
	)

	i := 0
	for c.Next() {
		if i > 0 {
			return nil, plugin.ErrOnce
		}
		i++

		l, err = ParseStanza(c)
		if err != nil {
			return ldap, err
		}
	}
	return ldap, nil
}

// ParseStanza parses a ldap stanza
func ParseStanza(c *caddy.Controller) (*Ldap, error) {

	ldap := New([]string{""})
	ldap.autoPathSearch = searchFromResolvConf()

	opts := dnsControlOpts{
		initEndpointsCache: true,
		ignoreEmptyService: false,
	}
	ldap.opts = opts

	zones := c.RemainingArgs()

	if len(zones) != 0 {
		ldap.Zones = zones
		for i := 0; i < len(ldap.Zones); i++ {
			ldap.Zones[i] = plugin.Host(ldap.Zones[i]).Normalize()
		}
	} else {
		ldap.Zones = make([]string, len(c.ServerBlockKeys))
		for i := 0; i < len(c.ServerBlockKeys); i++ {
			ldap.Zones[i] = plugin.Host(c.ServerBlockKeys[i]).Normalize()
		}
	}

	ldap.primaryZoneIndex = -1
	for i, z := range ldap.Zones {
		if dnsutil.IsReverse(z) > 0 {
			continue
		}
		ldap.primaryZoneIndex = i
		break
	}

	if ldap.primaryZoneIndex == -1 {
		return nil, errors.New("non-reverse zone name must be used")
	}

	ldap.Upstream = upstream.New()

	for c.NextBlock() {
		switch c.Val() {
		// RFC 4516 URL
		case "endpoint_pod_names":
			args := c.RemainingArgs()
			if len(args) > 0 {
				return nil, c.ArgErr()
			}
			ldap.endpointNameMode = true
			continue
		case "pods":
			args := c.RemainingArgs()
			if len(args) == 1 {
				switch args[0] {
				case podModeDisabled, podModeInsecure, podModeVerified:
					ldap.podMode = args[0]
				default:
					return nil, fmt.Errorf("wrong value for pods: %s,  must be one of: disabled, verified, insecure", args[0])
				}
				continue
			}
			return nil, c.ArgErr()
		case "namespaces":
			args := c.RemainingArgs()
			if len(args) > 0 {
				for _, a := range args {
					ldap.Namespaces[a] = struct{}{}
				}
				continue
			}
			return nil, c.ArgErr()
		case "endpoint":
			args := c.RemainingArgs()
			if len(args) > 0 {
				// Multiple endpoints are deprecated but still could be specified,
				// only the first one be used, though
				ldap.APIServerList = args
				if len(args) > 1 {
					log.Warningf("Multiple endpoints have been deprecated, only the first specified endpoint '%s' is used", args[0])
				}
				continue
			}
			return nil, c.ArgErr()
		case "tls": // cert key cacertfile
			args := c.RemainingArgs()
			if len(args) == 3 {
				ldap.APIClientCert, ldap.APIClientKey, ldap.APICertAuth = args[0], args[1], args[2]
				continue
			}
			return nil, c.ArgErr()
		case "labels":
			args := c.RemainingArgs()
			if len(args) > 0 {
				labelSelectorString := strings.Join(args, " ")
				ls, err := meta.ParseToLabelSelector(labelSelectorString)
				if err != nil {
					return nil, fmt.Errorf("unable to parse label selector value: '%v': %v", labelSelectorString, err)
				}
				ldap.opts.labelSelector = ls
				continue
			}
			return nil, c.ArgErr()
		case "namespace_labels":
			args := c.RemainingArgs()
			if len(args) > 0 {
				namespaceLabelSelectorString := strings.Join(args, " ")
				nls, err := meta.ParseToLabelSelector(namespaceLabelSelectorString)
				if err != nil {
					return nil, fmt.Errorf("unable to parse namespace_label selector value: '%v': %v", namespaceLabelSelectorString, err)
				}
				ldap.opts.namespaceLabelSelector = nls
				continue
			}
			return nil, c.ArgErr()
		case "fallthrough":
			ldap.Fall.SetZonesFromArgs(c.RemainingArgs())
		case "ttl":
			args := c.RemainingArgs()
			if len(args) == 0 {
				return nil, c.ArgErr()
			}
			t, err := strconv.Atoi(args[0])
			if err != nil {
				return nil, err
			}
			if t < 0 || t > 3600 {
				return nil, c.Errf("ttl must be in range [0, 3600]: %d", t)
			}
			ldap.ttl = uint32(t)
		case "transfer":
			tos, froms, err := parse.Transfer(c, false)
			if err != nil {
				return nil, err
			}
			if len(froms) != 0 {
				return nil, c.Errf("transfer from is not supported with this plugin")
			}
			ldap.TransferTo = tos
		case "noendpoints":
			if len(c.RemainingArgs()) != 0 {
				return nil, c.ArgErr()
			}
			ldap.opts.initEndpointsCache = false
		case "ignore":
			args := c.RemainingArgs()
			if len(args) > 0 {
				ignore := args[0]
				if ignore == "empty_service" {
					ldap.opts.ignoreEmptyService = true
					continue
				} else {
					return nil, fmt.Errorf("unable to parse ignore value: '%v'", ignore)
				}
			}
		case "kubeconfig":
			args := c.RemainingArgs()
			if len(args) == 2 {
				config := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
					&clientcmd.ClientConfigLoadingRules{ExplicitPath: args[0]},
					&clientcmd.ConfigOverrides{CurrentContext: args[1]},
				)
				ldap.ClientConfig = config
				continue
			}
			return nil, c.ArgErr()
		default:
			return nil, c.Errf("unknown property '%s'", c.Val())
		}
	}

	if len(ldap.Namespaces) != 0 && ldap.opts.namespaceLabelSelector != nil {
		return nil, c.Errf("namespaces and namespace_labels cannot both be set")
	}

	return ldap, nil
}
