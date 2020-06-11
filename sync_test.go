package ldap_test

import (
	"crypto/tls"
	"testing"
	"time"

	"gopkg.in/ldap.v3"

	. "github.com/xoe-labs/ldap/v0"
)

type mockClient struct{}

func (m *mockClient) Start()                     {}
func (m *mockClient) StartTLS(*tls.Config) error { return nil }
func (m *mockClient) Close()                     {}
func (m *mockClient) SetTimeout(time.Duration)   {}

func (m *mockClient) Bind(username, password string) error      { return nil }
func (m *mockClient) UnauthenticatedBind(username string) error { return nil }
func (m *mockClient) SimpleBind(*ldap.SimpleBindRequest) (*ldap.SimpleBindResult, error) {
	return nil, nil
}
func (m *mockClient) ExternalBind() error { return nil }

func (m *mockClient) Add(*ldap.AddRequest) error           { return nil }
func (m *mockClient) Del(*ldap.DelRequest) error           { return nil }
func (m *mockClient) Modify(*ldap.ModifyRequest) error     { return nil }
func (m *mockClient) ModifyDN(*ldap.ModifyDNRequest) error { return nil }

func (m *mockClient) Compare(dn, attribute, value string) (bool, error) { return false, nil }
func (m *mockClient) PasswordModify(*ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
	return nil, nil
}

func (m *mockClient) Search(*ldap.SearchRequest) (*ldap.SearchResult, error) { return nil, nil }
func (m *mockClient) SearchWithPaging(searchRequest *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
	return &ldap.SearchResult{
		Entries: []*ldap.Entry{{
			DN: "ou=ae-dir, cn=host1",
			Attributes: []*ldap.EntryAttribute{{
				Name: "aeFqdn",
				Values: []string{
					"host1.example.org.",
				},
			}, {
				Name: "ipHostNumber",
				Values: []string{
					"1.2.3.4",
				},
			}},
		}, {
			DN: "ou=ae-dir, cn=host2",
			Attributes: []*ldap.EntryAttribute{{
				Name: "aeFqdn",
				// Without ending "."
				Values: []string{
					"host2.example.org",
				},
			}, {
				Name: "ipHostNumber",
				Values: []string{
					"1.2.3.5",
				},
			}},
		}, {
			DN: "ou=ae-dir, cn=host3",
			Attributes: []*ldap.EntryAttribute{{
				Name: "aeFqdn",
				Values: []string{
					"host3.sample.example.org.",
				},
			}, {
				Name: "ipHostNumber",
				Values: []string{
					"1.2.3.6",
				},
			}},
		}},
	}, nil
}

// Create a new Ldap Plugin. Uses a mocked client.
func newTestLdapSync() *Ldap {
	ldap := New([]string{"example.org.", "www.example.org.", "example.org.", "sample.example.org."})
	ldap.Client = &mockClient{}
	ldap.SearchRequest.Attributes = []string{
		"aeFqdn", "ipHostNumber",
	}
	ldap.SearchRequest.BaseDN = "ou=ae-dir"
	ldap.SearchRequest.Filter = "(objectClass=aeNwDevice)"
	ldap.FqdnAttr = "aeFqdn"
	ldap.Ip4Attr = "ipHostNumber"

	return ldap
}

// TestUpdateZone tests a zone update.
func TestUpdateZone(t *testing.T) {
	ldap := newTestLdapSync()
	if err := ldap.UpdateZones(); err != nil {
		t.Fatalf("error updating zones: %v", err)
	}
}
