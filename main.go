package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Printf("\nWelcome to Email Checker!\n")
	fmt.Printf("Enter an email address to check, or type 'exit' to quit: ")

	for scanner.Scan() {
		input := scanner.Text()

		if input == "exit" || input == "quit" {
			fmt.Println("Exiting Email Checker...")
			return
		}

		// Check if input is a valid email address
		matched, _ := regexp.MatchString(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, input)
		if !matched {
			fmt.Printf("\nInvalid input: %s is not a valid email address\n", input)
			continue
		}

		checkDNSRecords(input)
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Error: Something went wrong from input: %v\n", err)
	}
}

func checkDNSRecords(email string) {
	var domain = strings.Split(email, "@")[1]
	var hasSPF bool
	var dmarcRecords, spfRecords []string
	errors := []string{}

	// Check MX record
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		errors = append(errors, fmt.Sprintf("No MX record found for domain %s", domain))
	}

	// Check SPF record
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		errors = append(errors, fmt.Sprintf("No TXT record found for domain %s", domain))
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			spfRecords = append(spfRecords, record)
			hasSPF = true
			break
		}
	}
	if !hasSPF {
		errors = append(errors, fmt.Sprintf("No SPF record found for domain %s", domain))
	}

	// Check DMARC record
	dmarcRecords, err = net.LookupTXT("_dmarc." + domain)
	if err != nil {
		errors = append(errors, fmt.Sprintf("No DMARC record found for domain %s", domain))
	}

	if len(errors) > 0 {
		fmt.Printf("\nEmail %s may not be valid for the following reasons:\n", email)
		for _, err := range errors {
			fmt.Println("-", err)
		}
		fmt.Printf("\nHowever, some valid emails may not have certain DNS records, or their DNS records may not be configured properly.\n")
	} else {
		fmt.Printf("\nEmail %s appears to be valid.\n\n", email)
		fmt.Printf("MX Records: %v\n", mxRecords)
		fmt.Printf("SPF Records: %v\n", spfRecords)
		fmt.Printf("DMARC Records: %v\n", dmarcRecords)
	}

	fmt.Printf("\nEnter an email address, or type 'exit' to quit: ")
}
