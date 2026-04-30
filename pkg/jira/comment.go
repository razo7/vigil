package jira

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func (c *Client) PostComment(ticketID, body string) error {
	url := fmt.Sprintf("%s/rest/api/3/issue/%s/comment", c.baseURL, ticketID)

	adfBody := map[string]interface{}{
		"body": map[string]interface{}{
			"version": 1,
			"type":    "doc",
			"content": []interface{}{
				map[string]interface{}{
					"type": "codeBlock",
					"attrs": map[string]interface{}{
						"language": "text",
					},
					"content": []interface{}{
						map[string]interface{}{
							"type": "text",
							"text": body,
						},
					},
				},
			},
		},
		"visibility": map[string]interface{}{
			"type":  "role",
			"value": "RH associate",
		},
	}

	data, err := json.Marshal(adfBody)
	if err != nil {
		return fmt.Errorf("marshaling comment: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating comment request: %w", err)
	}
	req.Header.Set("Authorization", c.authHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("posting comment to %s: %w", ticketID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Jira comment returned %d for %s: %s", resp.StatusCode, ticketID, string(respBody[:min(len(respBody), 200)]))
	}

	return nil
}
