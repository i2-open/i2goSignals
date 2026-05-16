package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	fmt.Println("(C)2026 Independent Identity Inc. Licensed Under APL 2.0")
	insecure := flag.Bool("k", false, "Insecure: skip TLS verification")
	timeout := flag.Duration("t", 5*time.Second, "Timeout for the request")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("Usage: health [-k] [-t timeout] <url>")
		os.Exit(1)
	}

	url := flag.Arg(0)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   *timeout,
	}

	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Printf("OK: %d\n", resp.StatusCode)
		os.Exit(0)
	}

	fmt.Printf("Failed: %d\n", resp.StatusCode)
	os.Exit(1)
}
