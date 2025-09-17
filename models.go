package katapult

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

var errUnsupportedRecordType = errors.New("unsupported record type")

// DNSRecord represents a DNS record in the API response.
type DNSRecord struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	TTL      int    `json:"ttl"`
	Priority uint   `json:"priority"`
	Content  string `json:"content"`
}

// DNSRecordAPIResponse represents an API response for a DNS record.
type DNSRecordAPIResponse struct {
	DNSRecord DNSRecord `json:"dns_record"`
}

// DNSRecordsAPIResponse represents an API response of DNS records.
type DNSRecordsAPIResponse struct {
	DNSRecords []DNSRecord `json:"dns_records"`
}

// DeletionAPIResponse represents an API response for a deletion.
type DeletionAPIResponse struct {
	Deleted bool `json:"deleted"`
}

// recordMetadata stores Katapult-specific metadata associated with DNS records.
type recordMetadata struct {
	ID string
}

// genericRecord is used for record types that do not have a dedicated libdns struct.
type genericRecord struct {
	record   libdns.RR
	metadata recordMetadata
}

// RR satisfies the libdns.Record interface.
func (r genericRecord) RR() libdns.RR {
	return r.record
}

// ToLibDNSRecord converts a DNSRecord to a libdns.Record.
func (p *Provider) ToLibDNSRecord(r DNSRecord) libdns.Record {
	ttl := time.Duration(r.TTL) * time.Second
	meta := recordMetadata{ID: r.ID}

	switch r.Type {
	case "A", "AAAA":
		if ip, err := netip.ParseAddr(r.Content); err == nil {
			return libdns.Address{
				Name:         r.Name,
				TTL:          ttl,
				IP:           ip,
				ProviderData: meta,
			}
		}
	case "CNAME":
		return libdns.CNAME{
			Name:         r.Name,
			TTL:          ttl,
			Target:       r.Content,
			ProviderData: meta,
		}
	case "MX":
		return libdns.MX{
			Name:         r.Name,
			TTL:          ttl,
			Preference:   uint16(r.Priority),
			Target:       r.Content,
			ProviderData: meta,
		}
	case "NS":
		return libdns.NS{
			Name:         r.Name,
			TTL:          ttl,
			Target:       r.Content,
			ProviderData: meta,
		}
	case "TXT":
		return libdns.TXT{
			Name:         r.Name,
			TTL:          ttl,
			Text:         r.Content,
			ProviderData: meta,
		}
	}

	return genericRecord{
		record: libdns.RR{
			Name: r.Name,
			TTL:  ttl,
			Type: r.Type,
			Data: r.Content,
		},
		metadata: meta,
	}
}

// FromLibDNSRecord converts a libdns.Record to an API request body.
func (p *Provider) FromLibDNSRecord(record libdns.Record) (map[string]interface{}, error) {
	rr := record.RR()
	properties := map[string]interface{}{
		"type": rr.Type,
		"name": rr.Name,
	}

	if ttl := ensureValidTTL(rr.TTL); ttl != nil {
		properties["ttl"] = ttl
	}

	content := map[string]interface{}{}

	switch r := record.(type) {
	case libdns.Address:
		content["ip_address"] = addrValue(r.IP, rr.Data)
	case *libdns.Address:
		if r != nil {
			content["ip_address"] = addrValue(r.IP, rr.Data)
		}
	case libdns.CNAME:
		content["hostname"] = fallbackString(r.Target, rr.Data)
	case *libdns.CNAME:
		if r != nil {
			content["hostname"] = fallbackString(r.Target, rr.Data)
		}
	case libdns.NS:
		content["hostname"] = fallbackString(r.Target, rr.Data)
	case *libdns.NS:
		if r != nil {
			content["hostname"] = fallbackString(r.Target, rr.Data)
		}
	case libdns.MX:
		content["hostname"] = fallbackString(r.Target, rr.Data)
		if r.Preference > 0 {
			properties["priority"] = int(r.Preference)
		}
	case *libdns.MX:
		if r != nil {
			content["hostname"] = fallbackString(r.Target, rr.Data)
			if r.Preference > 0 {
				properties["priority"] = int(r.Preference)
			}
		}
	case libdns.TXT:
		content["content"] = fallbackString(r.Text, rr.Data)
	case *libdns.TXT:
		if r != nil {
			content["content"] = fallbackString(r.Text, rr.Data)
		}
	default:
		fallbackContent, extra := fallbackContentFromRR(rr)
		if fallbackContent == nil {
			return nil, fmt.Errorf("%w: %s", errUnsupportedRecordType, rr.Type)
		}
		for k, v := range extra {
			properties[k] = v
		}
		content = fallbackContent
	}

	if len(content) == 0 {
		fallbackContent, extra := fallbackContentFromRR(rr)
		if fallbackContent == nil {
			return nil, fmt.Errorf("%w: %s", errUnsupportedRecordType, rr.Type)
		}
		for k, v := range extra {
			properties[k] = v
		}
		content = fallbackContent
	}

	properties["content"] = map[string]interface{}{
		rr.Type: content,
	}

	return properties, nil
}

func fallbackContentFromRR(rr libdns.RR) (map[string]interface{}, map[string]interface{}) {
	content := map[string]interface{}{}
	extra := map[string]interface{}{}

	switch rr.Type {
	case "A", "AAAA", "IPS":
		content["ip_address"] = rr.Data
	case "ALIAS", "CNAME", "NS", "PTR":
		content["hostname"] = rr.Data
	case "MX":
		host, priority := parseMXData(rr.Data)
		content["hostname"] = host
		if priority != nil && *priority > 0 {
			extra["priority"] = *priority
		}
	case "TXT":
		content["content"] = rr.Data
	default:
		return nil, nil
	}

	return content, extra
}

func parseMXData(data string) (string, *int) {
	fields := strings.Fields(data)
	if len(fields) == 0 {
		return data, nil
	}
	if len(fields) == 1 {
		return fields[0], nil
	}
	priority, err := strconv.Atoi(fields[0])
	if err != nil {
		return data, nil
	}
	return fields[1], &priority
}

func fallbackString(primary, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return primary
	}
	return fallback
}

func addrValue(ip netip.Addr, fallback string) string {
	if ip.IsValid() {
		return ip.String()
	}
	return fallback
}

func ensureValidTTL(rawTTL time.Duration) *int {
	ttl := int(rawTTL.Seconds())
	if ttl == 0 {
		return nil
	} else if ttl < 60 {
		minTTL := 60
		return &minTTL
	}
	return &ttl
}

func recordID(record libdns.Record) string {
	switch r := record.(type) {
	case libdns.Address:
		return metadataID(r.ProviderData)
	case *libdns.Address:
		if r != nil {
			return metadataID(r.ProviderData)
		}
	case libdns.CNAME:
		return metadataID(r.ProviderData)
	case *libdns.CNAME:
		if r != nil {
			return metadataID(r.ProviderData)
		}
	case libdns.MX:
		return metadataID(r.ProviderData)
	case *libdns.MX:
		if r != nil {
			return metadataID(r.ProviderData)
		}
	case libdns.NS:
		return metadataID(r.ProviderData)
	case *libdns.NS:
		if r != nil {
			return metadataID(r.ProviderData)
		}
	case libdns.TXT:
		return metadataID(r.ProviderData)
	case *libdns.TXT:
		if r != nil {
			return metadataID(r.ProviderData)
		}
	case genericRecord:
		return r.metadata.ID
	case *genericRecord:
		if r != nil {
			return r.metadata.ID
		}
	case libdns.RR:
		return ""
	case *libdns.RR:
		return ""
	}

	return metadataID(nil)
}

func setRecordID(record libdns.Record, id string) libdns.Record {
	if id == "" {
		return record
	}
	meta := recordMetadata{ID: id}

	switch r := record.(type) {
	case libdns.Address:
		r.ProviderData = meta
		return r
	case *libdns.Address:
		if r == nil {
			return r
		}
		copy := *r
		copy.ProviderData = meta
		return copy
	case libdns.CNAME:
		r.ProviderData = meta
		return r
	case *libdns.CNAME:
		if r == nil {
			return r
		}
		copy := *r
		copy.ProviderData = meta
		return copy
	case libdns.MX:
		r.ProviderData = meta
		return r
	case *libdns.MX:
		if r == nil {
			return r
		}
		copy := *r
		copy.ProviderData = meta
		return copy
	case libdns.NS:
		r.ProviderData = meta
		return r
	case *libdns.NS:
		if r == nil {
			return r
		}
		copy := *r
		copy.ProviderData = meta
		return copy
	case libdns.TXT:
		r.ProviderData = meta
		return r
	case *libdns.TXT:
		if r == nil {
			return r
		}
		copy := *r
		copy.ProviderData = meta
		return copy
	case genericRecord:
		r.metadata = meta
		return r
	case *genericRecord:
		if r == nil {
			return r
		}
		copy := *r
		copy.metadata = meta
		return copy
	case libdns.RR:
		return genericRecord{
			record:   r,
			metadata: meta,
		}
	case *libdns.RR:
		if r == nil {
			return r
		}
		return genericRecord{
			record:   *r,
			metadata: meta,
		}
	default:
		return genericRecord{
			record:   record.RR(),
			metadata: meta,
		}
	}
}

func metadataID(data any) string {
	switch v := data.(type) {
	case recordMetadata:
		return v.ID
	case *recordMetadata:
		if v != nil {
			return v.ID
		}
	case string:
		return v
	case map[string]string:
		return v["id"]
	case map[string]interface{}:
		if id, ok := v["id"]; ok {
			if s, ok := id.(string); ok {
				return s
			}
		}
	}
	return ""
}
