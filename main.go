package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const (
	ExpirationThresholdDays = 14
	TEST_MODE               = true // Set to false to use real API
)

type Certificate struct {
	Source    string
	Domain    string
	ExpiresAt time.Time
	DaysLeft  int
	CertID    string
	Status    string
}

type DigiCertCertificate struct {
	ID             int      `json:"id"`
	CommonName     string   `json:"common_name"`
	ValidTill      string   `json:"valid_till"` // DigiCert returns as string
	Status         string   `json:"status"`
	DNSNames       []string `json:"dns_names"`
	OrderValidTill string   `json:"order_valid_till"`
}

type DigiCertResponse struct {
	Orders []DigiCertOrder `json:"orders"`
	Page   DigiCertPage    `json:"page"`
}

type DigiCertOrder struct {
	Certificate DigiCertCertificate `json:"certificate"`
	Status      string              `json:"status"`
}

type DigiCertPage struct {
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

func getSecret(ctx context.Context, secretName string) (string, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := secretsmanager.NewFromConfig(cfg)
	result, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &secretName,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s: %w", secretName, err)
	}
	return *result.SecretString, nil
}

func handler(ctx context.Context) error {
	fmt.Println("Starting certificate expiration check...")

	// Get Slack webhook from Secrets Manager
	slackWebhook, err := getSecret(ctx, "cert-monitor/slack-webhook")
	if err != nil {
		return fmt.Errorf("failed to get Slack webhook from Secrets Manager: %w", err)
	}

	// Only get DigiCert key if not in test mode
	var digiCertKey string
	if !TEST_MODE {
		digiCertKey, err = getSecret(ctx, "cert-monitor/digicert-key")
		if err != nil {
			return fmt.Errorf("failed to get DigiCert API key from Secrets Manager: %w", err)
		}
	}

	var allCerts []Certificate

	// Get DigiCert certificates
	digiCerts, err := getDigiCertCertificates(digiCertKey)
	if err != nil {
		fmt.Printf("Error fetching DigiCert certs: %v\n", err)
	} else {
		allCerts = append(allCerts, digiCerts...)
	}

	// Get AWS ACM certificates
	awsCerts, err := getAWSCertificates(ctx)
	if err != nil {
		fmt.Printf("Error fetching AWS certs: %v\n", err)
	} else {
		allCerts = append(allCerts, awsCerts...)
	}

	// Filter for expiring certificates
	expiringCerts := filterExpiringCertificates(allCerts)

	if len(expiringCerts) > 0 {
		fmt.Printf("Found %d expiring certificates\n", len(expiringCerts))
		err = sendSlackNotification(expiringCerts, slackWebhook)
		if err != nil {
			return fmt.Errorf("failed to send Slack notification: %w", err)
		}
		fmt.Println("Slack notification sent successfully")
	} else {
		fmt.Println("No certificates expiring within threshold")
	}

	return nil
}

func getDigiCertCertificates(apiKey string) ([]Certificate, error) {
	if TEST_MODE {
		return getMockDigiCertCertificates(), nil
	}

	if apiKey == "" {
		return nil, fmt.Errorf("DigiCert API key is empty")
	}

	var allCerts []Certificate
	offset := 0
	limit := 100

	for {
		// Correct endpoint: /order/certificate with filters
		url := fmt.Sprintf("https://www.digicert.com/services/v2/order/certificate?offset=%d&limit=%d&status=issued", offset, limit)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("X-DC-DEVKEY", apiKey)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("DigiCert API error: %d - %s", resp.StatusCode, string(body))
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		var dcResp DigiCertResponse
		if err := json.Unmarshal(body, &dcResp); err != nil {
			return nil, fmt.Errorf("failed to parse DigiCert response: %w", err)
		}

		// Process orders
		for _, order := range dcResp.Orders {
			cert := order.Certificate

			// Parse the expiration date
			// DigiCert format: "2024-12-31T23:59:59+00:00" or "2024-12-31"
			var expiresAt time.Time

			// Try multiple date formats
			formats := []string{
				time.RFC3339,
				"2006-01-02T15:04:05-07:00",
				"2006-01-02",
			}

			parsed := false
			for _, format := range formats {
				if t, err := time.Parse(format, cert.ValidTill); err == nil {
					expiresAt = t
					parsed = true
					break
				}
			}

			if !parsed {
				fmt.Printf("Warning: Could not parse date for cert %d: %s\n", cert.ID, cert.ValidTill)
				continue
			}

			daysLeft := int(time.Until(expiresAt).Hours() / 24)

			allCerts = append(allCerts, Certificate{
				Source:    "DigiCert",
				Domain:    cert.CommonName,
				ExpiresAt: expiresAt,
				DaysLeft:  daysLeft,
				CertID:    fmt.Sprintf("%d", cert.ID),
				Status:    order.Status,
			})
		}

		// Check if we need to paginate
		if offset+limit >= dcResp.Page.Total {
			break
		}
		offset += limit
	}

	return allCerts, nil
}

func getAWSCertificates(ctx context.Context) ([]Certificate, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	client := acm.NewFromConfig(cfg)

	// List Certificates
	listOutput, err := client.ListCertificates(ctx, &acm.ListCertificatesInput{})
	if err != nil {
		return nil, err
	}

	var certs []Certificate

	for _, certSummary := range listOutput.CertificateSummaryList {
		// Get detailed certificate information
		descOutput, err := client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
			CertificateArn: certSummary.CertificateArn,
		})
		if err != nil {
			fmt.Printf("Error describing certificate %s: %v\n", *certSummary.CertificateArn, err)
			continue
		}

		cert := descOutput.Certificate
		if cert.NotAfter == nil {
			continue
		}

		daysLeft := int(time.Until(*cert.NotAfter).Hours() / 24)

		status := "UNKNOWN"
		if cert.Status != "" {
			status = string(cert.Status)
		}

		certs = append(certs, Certificate{
			Source:    "AWS ACM",
			Domain:    *cert.DomainName,
			ExpiresAt: *cert.NotAfter,
			DaysLeft:  daysLeft,
			CertID:    *certSummary.CertificateArn,
			Status:    status,
		})
	}
	return certs, nil
}

func filterExpiringCertificates(certs []Certificate) []Certificate {
	var expiring []Certificate

	for _, cert := range certs {
		if cert.DaysLeft <= ExpirationThresholdDays && cert.DaysLeft >= 0 {
			expiring = append(expiring, cert)
		}
	}

	// Sort by days left (most urgent first
	sort.Slice(expiring, func(i, j int) bool {
		return expiring[i].DaysLeft < expiring[j].DaysLeft
	})

	return expiring
}

func sendSlackNotification(certs []Certificate, webhookURL string) error {
	if webhookURL == "" {
		return fmt.Errorf("Slack webhook URL is empty")
	}

	// Build message blocks
	blocks := buildSlackMessage(certs)

	payload := map[string]interface{}{
		"blocks": blocks,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Slack API error: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

func buildSlackMessage(certs []Certificate) []map[string]interface{} {
	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]string{
				"type": "plain_text",
				"text": "Certificate Expiration Alert",
			},
		},
		{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*%d* certificates expiring within *%d* days", len(certs), ExpirationThresholdDays),
			},
		},
		{
			"type": "divider",
		},
	}

	for _, cert := range certs {
		urgency := "🟡"
		if cert.DaysLeft <= 3 {
			urgency = "🔴"
		} else if cert.DaysLeft <= 7 {
			urgency = "🔴"
		}

		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": fmt.Sprintf("%s *%s*\n"+
					"Source: `%s` | Status: `%s`\n"+
					"Expires: `%s` (*%d days left*)",
					urgency,
					cert.Domain,
					cert.Source,
					cert.Status,
					cert.ExpiresAt.Format("Jan 02, 2006 15:04 MST"),
					cert.DaysLeft,
				),
			},
		})
	}

	return blocks
}

func getMockDigiCertCertificates() []Certificate {
	now := time.Now()

	// Simulating the Order → Certificate structure from DigiCert API
	return []Certificate{
		{
			Source:    "DigiCert",
			Domain:    "test-expiring-soon.example.com",
			ExpiresAt: now.AddDate(0, 0, 5),
			DaysLeft:  5,
			CertID:    "Order:12345/Cert:67890", // Shows it came from an order
			Status:    "issued",                 // This would be order.Status in real response
		},
		{
			Source:    "DigiCert",
			Domain:    "test-critical.example.com",
			ExpiresAt: now.AddDate(0, 0, 2),
			DaysLeft:  2,
			CertID:    "Order:12346/Cert:67891",
			Status:    "issued",
		},
		{
			Source:    "DigiCert",
			Domain:    "test-warning.example.com",
			ExpiresAt: now.AddDate(0, 0, 10),
			DaysLeft:  10,
			CertID:    "Order:12347/Cert:67892",
			Status:    "issued",
		},
		{
			Source:    "DigiCert",
			Domain:    "test-safe-wont-alert.example.com",
			ExpiresAt: now.AddDate(0, 0, 60),
			DaysLeft:  60,
			CertID:    "Order:12348/Cert:67893",
			Status:    "issued",
		},
	}
}

func main() {
	// Local testing mode
	if len(os.Args) > 1 && os.Args[1] == "test" {
		fmt.Println("Running in TEST MODE...")
		if err := handler(context.Background()); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Lambda mode
	lambda.Start(handler)
}
