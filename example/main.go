package main

import (
	"context"
	"fmt"
	"os"

	"github.com/libdns/katapult"
	"github.com/libdns/libdns"
)

var (
	envToken = os.Getenv("LIBDNS_KATAPULT_API_TOKEN")
	envZone  = os.Getenv("LIBDNS_KATAPULT_ZONE")
)
func main() {
	p := katapult.Provider{APIToken: envToken}

	records, err := p.SetRecords(context.TODO(), envZone, []libdns.Record{
		libdns.TXT{
			Name: "testrecord",
			TTL:  0,
			Text: "hello world",
		},
	})

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	recordsToDelete := []libdns.Record{}

	for _, r := range records {
		fmt.Println("Set:", r)

		// Call .RR() on record before deleting it as it drops provider specific metadata
		recordsToDelete = append(recordsToDelete, r.RR())
	}

	// Update the record with new text
	updatedRecords, err := p.SetRecords(context.TODO(), envZone, []libdns.Record{
		libdns.TXT{
			Name: "testrecord",
			TTL:  0,
			Text: "updated text",
		},
	})

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	for _, r := range updatedRecords {
		fmt.Println("Updated:", r)
	}

	deletedRecords, err := p.DeleteRecords(context.TODO(), envZone, recordsToDelete)

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Deleted:", deletedRecords)
}
