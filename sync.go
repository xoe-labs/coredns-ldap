package ldap

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/file"
	"github.com/miekg/dns"
)

// Run updates the zone from ldap.
func (l *Ldap) Run(ctx context.Context) error {
	if err := l.UpdateZones(); err != nil {
		return err
	}

	loop := func() {
		for {
			select {
			case <-ctx.Done():
				log.Infof("Breaking out of Ldap update loop: %v", ctx.Err())
				return
			case <-time.After(l.syncInterval):
				if err := l.UpdateZones(); err != nil && ctx.Err() == nil {
					log.Errorf("Failed to update zones: %v", err)
				}
			}
		}
	}
	go loop()

	return nil
}

func (l *Ldap) UpdateZones() error {
	zoneFileMap := make(map[string]*file.Zone, len(l.Zones.Names))
	for _, zn := range l.Zones.Names {
		zoneFileMap[zn] = nil
		zoneFileMap[zn] = file.NewZone(zn, "")
		zoneFileMap[zn].Upstream = l.Upstream

		err := zoneFileMap[zn].Insert(SOA(zn))
		if err != nil {
			return fmt.Errorf("updating zones: %w", err)
		}
	}

	ldapRecords, err := l.fetchLdapRecords()
	if err != nil {
		return fmt.Errorf("updating zones: %w", err)
	}

	for zn, lrpz := range l.mapLdapRecordsToZone(ldapRecords) {
		if len(lrpz) == 0 {
			continue
		}

		for _, lr := range lrpz {
			err = zoneFileMap[zn].Insert(lr.AAAA())
			err = zoneFileMap[zn].Insert(lr.A())
			if err != nil {
				return fmt.Errorf("updating zones: %w", err)
			}
		}
	}

	l.zMu.Lock()
	for zn, zf := range zoneFileMap {
		l.Zones.Z[zn] = zf
	}
	l.zMu.Unlock()

	return nil
}

func (l *Ldap) mapLdapRecordsToZone(ldapRecords []ldapRecord) (ldapRecordsPerZone map[string][]ldapRecord) {
	lrpz := make(map[string][]ldapRecord, len(l.Zones.Names))
	for _, zn := range l.Zones.Names {
		lrpz[zn] = nil
	}

	for _, lr := range ldapRecords {
		zone := plugin.Zones(l.Zones.Names).Matches(lr.fqdn)
		if zone != "" {
			lrpz[zone] = append(lrpz[zone], lr)
		}
	}

	return lrpz
}

func (l *Ldap) fetchLdapRecords() (ldapRecords []ldapRecord, err error) {
	l.Ptr = make(map[string]string)
	searchResult, err := l.Client.SearchWithPaging(l.SearchRequest, l.pagingLimit)
	if err != nil {
		return nil, fmt.Errorf("fetching data from server: %w", err)
	}

	ldapRecords = make([]ldapRecord, len(searchResult.Entries))
	for i := 0; i < len(ldapRecords); i++ {
		fqdn := searchResult.Entries[i].GetAttributeValue(l.FqdnAttr)
		if !strings.HasSuffix(fqdn, ".") {
			fqdn = fqdn + "."
		}
		ldapRecords[i] = ldapRecord{
			fqdn: fqdn,
			ip4:  net.ParseIP(searchResult.Entries[i].GetAttributeValue(l.Ip4Attr)),
			ip6:  net.ParseIP(searchResult.Entries[i].GetAttributeValue(l.Ip6Attr)),
		}
		ipv6Arpa, err := dns.ReverseAddr(net.ParseIP(searchResult.Entries[i].GetAttributeValue(l.Ip6Attr)).String())
		if err == nil {
			l.Ptr[ipv6Arpa] = fqdn
		}
	}

	return ldapRecords, nil
}
