# nvd [![Go Report](https://goreportcard.com/badge/github.com/daehee/nvd)](https://goreportcard.com/report/github.com/daehee/nvd)

Fast, simple library in Go to fetch CVEs from the NVD (U.S. National Vulnerability Database) feeds.

## Install

```
go get github.com/daehee/nvd
```

## Usage

The `nvd` package provides a `Client` for fetching CVEs from the official NVD feeds:
```go
// nvd client with ./tmp working dir
client, err := NewClient("tmp")

// Fetch single CVE
cve, err := client.FetchCVE("CVE-2020-14882")

// Fetch all recently published and modified CVES
cves, err := client.FetchUpdatedCVEs()
```

## License

[MIT License](LICENSE)