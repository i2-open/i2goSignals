package main

import (
    "fmt"
    "net/url"
    "strings"
)

func main() {

    fmt.Println("Hello, World!")

    values := []string{"https://example.com/path", "example.com", "example", "example.com?param=value", "example.com/path?param=value"}

    for _, value := range values {
        isURL := false
        needsEncoding := false
        parsedURL, err := url.Parse(value)
        if err == nil && parsedURL.Scheme != "" && parsedURL.Host != "" {
            isURL = true
            if parsedURL.RawQuery != "" || strings.Contains(parsedURL.Path, " ") {
                needsEncoding = true
            }
        } else if err == nil && strings.Contains(value, ".") && !strings.Contains(value, "/") {
            // Check if it looks like a domain without scheme
            if _, err := url.Parse("https://" + value); err == nil {
                isURL = true
                if strings.Contains(value, "?") || strings.Contains(value, " ") {
                    needsEncoding = true
                }
            }
        } else if strings.Contains(value, "?") || strings.Contains(value, " ") {
            needsEncoding = true
        }

        urlEscape := url.QueryEscape(value)
        msg := fmt.Sprintf("%s \t= %s \t(isURL: %v, needsEncoding: %v)", value, urlEscape, isURL, needsEncoding)
        fmt.Println(msg)

        val2, err := url.QueryUnescape(value)
        if err != nil {
            fmt.Println("Unescape value error: " + err.Error())
        }
        val3, err := url.QueryUnescape(urlEscape)
        if err != nil {
            fmt.Println("Escaped value error: " + err.Error())
        }
        fmt.Printf("%s \t= %s \t= %s\n\n", value, val2, val3)
    }

}
