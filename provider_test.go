package katapult

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

var (
	envToken = ""
	envZone  = ""
)

func provisionRecords(t *testing.T, provider *Provider, zone string, recordsToProvision []libdns.Record, recordsToTest []libdns.Record) []libdns.Record {
	t.Helper()

	provisionedRecords, err := provider.AppendRecords(context.Background(), zone, recordsToProvision)
	if err != nil {
		t.Fatalf("failed to create records: %v", err)
	}

	if len(provisionedRecords) > 0 {
		actualID := recordID(provisionedRecords[0])
		for i, record := range recordsToTest {
			if recordID(record) != "" {
				recordsToTest[i] = setRecordID(record, actualID)
			}
		}
	}

	return provisionedRecords
}

func cleanupRecords(t *testing.T, provider *Provider, records []libdns.Record) {
	t.Helper()

	_, err := provider.DeleteRecords(context.Background(), envZone, records)
	if err != nil {
		t.Fatalf("failed to delete records: %v", err)
	}
}

func assertErrorIs(t *testing.T, actual, expected error) {
	t.Helper()

	if expected == nil {
		if actual != nil {
			t.Fatalf("expected no error, but got: %v", actual)
		}
	} else {
		if !errors.Is(actual, expected) {
			t.Fatalf("expected error %v, but got: %v", expected, actual)
		}
	}
}

func assertRecordListsEqual(t *testing.T, actual, expected []libdns.Record) {
	t.Helper()

	if len(actual) != len(expected) {
		t.Fatalf("expected %d records, but got %d", len(expected), len(actual))
	}

	for i := range expected {
		actualRR := actual[i].RR()
		expectedRR := expected[i].RR()

		if recordID(actual[i]) == "" {
			t.Fatalf("expected record ID to be present, but got empty for %s %s", actualRR.Type, actualRR.Name)
		}
		if actualRR.Type != expectedRR.Type {
			t.Fatalf("expected record Type %s, but got %s", expectedRR.Type, actualRR.Type)
		}
		if actualRR.Name != expectedRR.Name {
			t.Fatalf("expected record Name %s, but got %s", expectedRR.Name, actualRR.Name)
		}
		if actualRR.Data != expectedRR.Data {
			t.Fatalf("expected record Data %s, but got %s", expectedRR.Data, actualRR.Data)
		}
		if actualRR.TTL != expectedRR.TTL {
			t.Fatalf("expected record TTL %v, but got %v", expectedRR.TTL, actualRR.TTL)
		}
	}
}

func TestGetRecords(t *testing.T) {
	input := map[string]struct {
		zone               string
		recordsToProvision []libdns.Record
		expectedRecords    []libdns.Record
		expectedErr        error
	}{
		"Success": {
			zone: envZone + ".",
			recordsToProvision: []libdns.Record{
				libdns.Address{
					Name: "example.com",
					TTL:  300 * time.Second,
					IP:   netip.MustParseAddr("127.0.0.1"),
				},
			},
			expectedRecords: []libdns.Record{
				libdns.Address{
					Name: "example.com",
					TTL:  300 * time.Second,
					IP:   netip.MustParseAddr("127.0.0.1"),
				},
			},
		},
		"API Error": {
			zone:        "_",
			expectedErr: errUnexpectedStatusCode,
		},
	}

	for name, data := range input {
		t.Run(name, func(t *testing.T) {
			provider := &Provider{APIToken: envToken}
			resultFromProvision := provisionRecords(t, provider, data.zone, data.recordsToProvision, []libdns.Record{})
			defer cleanupRecords(t, provider, resultFromProvision)

			records, err := provider.GetRecords(context.Background(), data.zone)
			assertErrorIs(t, err, data.expectedErr)
			assertRecordListsEqual(t, records, data.expectedRecords)
		})
	}
}

func TestAppendRecords(t *testing.T) {
	input := map[string]struct {
		zone            string
		recordsToAdd    []libdns.Record
		expectedRecords []libdns.Record
		expectedErr     error
	}{
		"Success": {
			zone: envZone + ".",
			recordsToAdd: []libdns.Record{
				libdns.CNAME{
					Name:   "test",
					Target: "test",
				},
			},
			expectedRecords: []libdns.Record{
				libdns.CNAME{
					Name:   "test",
					Target: "test." + envZone,
				},
			},
		},
		"API Error": {
			zone: "_",
			recordsToAdd: []libdns.Record{
				libdns.CNAME{
					Name:   "test",
					Target: "test",
					TTL:    300 * time.Second,
				},
			},
			expectedErr: errUnexpectedStatusCode,
		},
	}

	for name, data := range input {
		t.Run(name, func(t *testing.T) {
			provider := &Provider{APIToken: envToken}
			addedRecords, err := provider.AppendRecords(context.Background(), data.zone, data.recordsToAdd)
			defer cleanupRecords(t, provider, addedRecords)
			assertErrorIs(t, err, data.expectedErr)
			assertRecordListsEqual(t, addedRecords, data.expectedRecords)
		})
	}
}

func TestSetRecords(t *testing.T) {
	input := map[string]struct {
		zone               string
		recordsToProvision []libdns.Record
		recordsToSet       []libdns.Record
		expectedRecords    []libdns.Record
		expectedErr        error
	}{
		"Success": {
			zone: envZone + ".",
			recordsToProvision: []libdns.Record{
				libdns.Address{
					Name: "testrecord.com",
					TTL:  300 * time.Second,
					IP:   netip.MustParseAddr("0.0.0.0"),
				},
			},
			recordsToSet: []libdns.Record{
				setRecordID(libdns.TXT{
					Name: "testrecord.com",
					TTL:  300 * time.Second,
					Text: "hello",
				}, "existingrecord"),
				libdns.Address{
					Name: "newrecord.com",
					TTL:  300 * time.Second,
					IP:   netip.MustParseAddr("0.0.0.0"),
				},
			},
			expectedRecords: []libdns.Record{
				libdns.TXT{
					Name: "testrecord.com",
					TTL:  300 * time.Second,
					Text: "hello",
				},
				libdns.Address{
					Name: "newrecord.com",
					TTL:  300 * time.Second,
					IP:   netip.MustParseAddr("0.0.0.0"),
				},
			},
		},
		"API Error": {
			zone: "_",
			recordsToSet: []libdns.Record{
				libdns.Address{
					Name: "newrecord.com",
					TTL:  300 * time.Second,
					IP:   netip.MustParseAddr("0.0.0.0"),
				},
			},
			expectedErr: errUnexpectedStatusCode,
		},
	}

	for name, data := range input {
		t.Run(name, func(t *testing.T) {
			provider := &Provider{APIToken: envToken}
			provisionRecords(t, provider, data.zone, data.recordsToProvision, data.recordsToSet)

			updatedRecords, err := provider.SetRecords(context.Background(), data.zone, data.recordsToSet)
			defer cleanupRecords(t, provider, updatedRecords)
			assertErrorIs(t, err, data.expectedErr)
			assertRecordListsEqual(t, updatedRecords, data.expectedRecords)
		})
	}
}

func TestDeleteRecords(t *testing.T) {
	input := map[string]struct {
		zone               string
		recordsToProvision []libdns.Record
		recordsToDelete    []libdns.Record
		expectedRecords    []libdns.Record
		expectedErr        error
	}{
		"Success": {
			zone: envZone + ".",
			recordsToProvision: []libdns.Record{
				libdns.Address{
					Name: "testrecord.com",
					TTL:  300 * time.Second,
					IP:   netip.MustParseAddr("0.0.0.0"),
				},
			},
			recordsToDelete: []libdns.Record{
				setRecordID(libdns.Address{
					Name: "testrecord.com",
					IP:   netip.MustParseAddr("0.0.0.0"),
				}, "existingrecord"),
			},
			expectedRecords: []libdns.Record{
				libdns.Address{
					Name: "testrecord.com",
					IP:   netip.MustParseAddr("0.0.0.0"),
				},
			},
		},
		"API Error": {
			zone: "_",
			recordsToDelete: []libdns.Record{
				setRecordID(libdns.Address{
					Name: "example.com",
				}, "existingrecord"),
			},
			expectedErr: errUnexpectedStatusCode,
		},
	}

	for name, data := range input {
		t.Run(name, func(t *testing.T) {
			provider := &Provider{APIToken: envToken}
			provisionRecords(t, provider, data.zone, data.recordsToProvision, data.recordsToDelete)

			deletedRecords, err := provider.DeleteRecords(context.Background(), data.zone, data.recordsToDelete)
			assertErrorIs(t, err, data.expectedErr)
			assertRecordListsEqual(t, deletedRecords, data.expectedRecords)
		})
	}
}

func TestMain(m *testing.M) {
	envToken = os.Getenv("LIBDNS_KATAPULT_API_TOKEN")
	envZone = os.Getenv("LIBDNS_KATAPULT_ZONE")

	if len(envToken) == 0 || len(envZone) == 0 {
		fmt.Println(`Please note that these tests use the Katapult API.
		You should create a new and empty domain/zone to avoid modifying any production data.
		Specify 'LIBDNS_KATAPULT_API_TOKEN' and 'LIBDNS_KATAPULT_ZONE' to continue.`)
		os.Exit(1)
	}

	os.Exit(m.Run())
}
