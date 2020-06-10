package ldap

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/file"
)

// Run updates the zone from ldap.
func (l *Ldap) Run(ctx context.Context) error {
	if err := l.updateZones(ctx); err != nil {
		return err
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Infof("Breaking out of Ldap update loop: %v", ctx.Err())
				return
			case <-time.After(l.syncInterval):
				if err := l.updateZones(ctx); err != nil && ctx.Err() == nil {
					log.Errorf("Failed to update zones: %v", err)
				}
			}
		}
	}()
	return nil
}

func (l *Ldap) updateZones(ctx context.Context) error {
	zoneFileMap := make(map[string]*file.Zone, len(l.Zones.Names))
	for _, zn := range l.Zones.Names {
		zoneFileMap[zn] = nil
	}
	ldapRecords, err := l.fetchLdapRecords()
	if err != nil {
		return fmt.Errorf("updating zones: %w", err)
	}
	for zn, lrpz := range l.mapLdapRecordsToZone(ldapRecords) {
		if lrpz == nil {
			continue
		}
		if zoneFileMap[zn] == nil {
			zoneFileMap[zn] = file.NewZone(zn, "")
			zoneFileMap[zn].Upstream = l.Upstream
			zoneFileMap[zn].Insert(SOA(zn))
		}
		for _, lr := range lrpz {
			zoneFileMap[zn].Insert(lr.A())
		}
	}
	l.zMu.Lock()
	for zn, zf := range zoneFileMap {
    		// TODO: assignement copies lock value from file.Zone
		(*l.Zones.Z[zn]) = *zf
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
	searchResult, err := l.Client.SearchWithPaging(l.searchRequest, l.pagingLimit)
	if err != nil {
		return nil, fmt.Errorf("fetching data from server: %w", err)
	}
	ldapRecords = make([]ldapRecord, len(searchResult.Entries))
	for i := 0; i < len(ldapRecords); i++ {
		ldapRecords[i] = ldapRecord{
			fqdn: searchResult.Entries[i].GetAttributeValue(l.fqdnAttr),
			ip:   net.ParseIP(searchResult.Entries[i].GetAttributeValue(l.ip4Attr)),
		}
	}
	return ldapRecords, nil
}
