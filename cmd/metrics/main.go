package main

import (
    "bufio"
    "fmt"
    "net/http"
    "os"
    "strings"

    "github.com/i2-open/i2goSignals/pkg/httpSupport"
)

func main() {
    fmt.Println("(C)2026 Independent Identity Inc. Licensed Under APL 2.0")
    metricsURL := os.Getenv("GOSIGNALS_METRICS_URL")
    if metricsURL == "" {
        metricsURL = "http://localhost:8080/metrics"
    }

    fmt.Printf("Fetching metrics from %s...\n\n", metricsURL)

    resp, err := http.Get(metricsURL)
    if err != nil {
        fmt.Printf("Error fetching metrics: %v\n", err)
        os.Exit(1)
    }
    defer httpSupport.HandleRespClose(resp)

    if resp.StatusCode != http.StatusOK {
        fmt.Printf("Server returned non-200 status: %d\n", resp.StatusCode)
        os.Exit(1)
    }

    scanner := bufio.NewScanner(resp.Body)
    fmt.Println("--- goSignals Specific Metrics ---")
    for scanner.Scan() {
        line := scanner.Text()
        // Filter for custom goSignals metrics or show all if needed
        if strings.HasPrefix(line, "goSignals_") {
            fmt.Println(line)
        }
    }

    if err := scanner.Err(); err != nil {
        fmt.Printf("Error reading response: %v\n", err)
    }
}
