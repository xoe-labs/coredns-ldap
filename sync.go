package ldap

import (
	"context"
	"fmt"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/file"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
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
			case <-time.After(l.syncInterval * time.Second):
				if err := l.updateZones(ctx); err != nil && ctx.Err() == nil {
					log.Errorf("Failed to update zones: %v", err)
				}
			}
		}
	}()
	return nil
}

func (l *Ldap) updateZones(ctx context.Context) error {
	var err error
	var zoneFile file.Zone

	valuePairs, err := getValuePairs()
	for _, z := range l.Zones {
                zoneFile = file.NewZone(z, "")
                zoneFile.Upstream = l.Upstream
        	l.zMu.Lock()
        	(*z[i]).z = zoneFile
        	l.zMu.Unlock()
    	}
	if err != nil {
		return fmt.Errorf("error updating zones: %v", err)
	}
	return nil

}

func (l *Ldap) getValuePairs() (valuePairs *[][]string, err error) {
	searchResult, err := l.Client.SearchWithPaging(l.searchRequest, l.pagingLimit)
	if err != nil {
		return nil, fmt.Errorf("error fetching data from ldap server: %w", err)
	}

}

func updateZoneFromPublicResourceSet(recordSet publicdns.RecordSetListResultPage, zName string) *file.Zone {
	zoneFile := file.NewZone(zName, "")

	for _, result := range *(recordSet.Response().Value) {
		resultFqdn := *(result.RecordSetProperties.Fqdn)
		resultTTL := uint32(*(result.RecordSetProperties.TTL))
		if result.RecordSetProperties.ARecords != nil {
			for _, A := range *(result.RecordSetProperties.ARecords) {
				a := &dns.A{Hdr: dns.RR_Header{Name: resultFqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: resultTTL},
					A: net.ParseIP(*(A.Ipv4Address))}
				zoneFile.Insert(a)
			}
		}

		if result.RecordSetProperties.AaaaRecords != nil {
			for _, AAAA := range *(result.RecordSetProperties.AaaaRecords) {
				aaaa := &dns.AAAA{Hdr: dns.RR_Header{Name: resultFqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: resultTTL},
					AAAA: net.ParseIP(*(AAAA.Ipv6Address))}
				zoneFile.Insert(aaaa)
			}
		}

		if result.RecordSetProperties.MxRecords != nil {
			for _, MX := range *(result.RecordSetProperties.MxRecords) {
				mx := &dns.MX{Hdr: dns.RR_Header{Name: resultFqdn, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: resultTTL},
					Preference: uint16(*(MX.Preference)),
					Mx:         dns.Fqdn(*(MX.Exchange))}
				zoneFile.Insert(mx)
			}
		}

		if result.RecordSetProperties.PtrRecords != nil {
			for _, PTR := range *(result.RecordSetProperties.PtrRecords) {
				ptr := &dns.PTR{Hdr: dns.RR_Header{Name: resultFqdn, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: resultTTL},
					Ptr: dns.Fqdn(*(PTR.Ptrdname))}
				zoneFile.Insert(ptr)
			}
		}

		if result.RecordSetProperties.SrvRecords != nil {
			for _, SRV := range *(result.RecordSetProperties.SrvRecords) {
				srv := &dns.SRV{Hdr: dns.RR_Header{Name: resultFqdn, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: resultTTL},
					Priority: uint16(*(SRV.Priority)),
					Weight:   uint16(*(SRV.Weight)),
					Port:     uint16(*(SRV.Port)),
					Target:   dns.Fqdn(*(SRV.Target))}
				zoneFile.Insert(srv)
			}
		}

		if result.RecordSetProperties.TxtRecords != nil {
			for _, TXT := range *(result.RecordSetProperties.TxtRecords) {
				txt := &dns.TXT{Hdr: dns.RR_Header{Name: resultFqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: resultTTL},
					Txt: *(TXT.Value)}
				zoneFile.Insert(txt)
			}
		}

		if result.RecordSetProperties.NsRecords != nil {
			for _, NS := range *(result.RecordSetProperties.NsRecords) {
				ns := &dns.NS{Hdr: dns.RR_Header{Name: resultFqdn, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: resultTTL},
					Ns: *(NS.Nsdname)}
				zoneFile.Insert(ns)
			}
		}

		if result.RecordSetProperties.SoaRecord != nil {
			SOA := result.RecordSetProperties.SoaRecord
			soa := &dns.SOA{Hdr: dns.RR_Header{Name: resultFqdn, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: resultTTL},
				Minttl:  uint32(*(SOA.MinimumTTL)),
				Expire:  uint32(*(SOA.ExpireTime)),
				Retry:   uint32(*(SOA.RetryTime)),
				Refresh: uint32(*(SOA.RefreshTime)),
				Serial:  uint32(*(SOA.SerialNumber)),
				Mbox:    dns.Fqdn(*(SOA.Email)),
				Ns:      *(SOA.Host)}
			zoneFile.Insert(soa)
		}

		if result.RecordSetProperties.CnameRecord != nil {
			CNAME := result.RecordSetProperties.CnameRecord.Cname
			cname := &dns.CNAME{Hdr: dns.RR_Header{Name: resultFqdn, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: resultTTL},
				Target: dns.Fqdn(*CNAME)}
			zoneFile.Insert(cname)
		}
	}
	return zoneFile
}
