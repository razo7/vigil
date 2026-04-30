package jira

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Transition struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (c *Client) GetTransitions(ticketID string) ([]Transition, error) {
	url := fmt.Sprintf("%s/rest/api/3/issue/%s/transitions", c.baseURL, ticketID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", c.authHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching transitions for %s: %w", ticketID, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Jira transitions returned %d for %s: %s", resp.StatusCode, ticketID, string(body[:min(len(body), 200)]))
	}

	var result struct {
		Transitions []Transition `json:"transitions"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing transitions: %w", err)
	}

	return result.Transitions, nil
}

func (c *Client) TransitionTicket(ticketID, targetStatus string) error {
	transitions, err := c.GetTransitions(ticketID)
	if err != nil {
		return fmt.Errorf("getting transitions: %w", err)
	}

	var transitionID string
	for _, t := range transitions {
		if strings.EqualFold(t.Name, targetStatus) {
			transitionID = t.ID
			break
		}
	}
	if transitionID == "" {
		available := make([]string, len(transitions))
		for i, t := range transitions {
			available[i] = t.Name
		}
		return fmt.Errorf("no transition to %q for %s (available: %s)", targetStatus, ticketID, strings.Join(available, ", "))
	}

	payload := map[string]interface{}{
		"transition": map[string]string{"id": transitionID},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling transition: %w", err)
	}

	url := fmt.Sprintf("%s/rest/api/3/issue/%s/transitions", c.baseURL, ticketID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating transition request: %w", err)
	}
	req.Header.Set("Authorization", c.authHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("transitioning %s: %w", ticketID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Jira transition returned %d for %s: %s", resp.StatusCode, ticketID, string(respBody[:min(len(respBody), 200)]))
	}

	return nil
}

func (c *Client) LinkPR(ticketID, prURL, prTitle string) error {
	payload := map[string]interface{}{
		"object": map[string]interface{}{
			"url":   prURL,
			"title": prTitle,
			"icon": map[string]string{
				"url16x16": "https://github.com/favicon.ico",
				"title":    "GitHub PR",
			},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling link: %w", err)
	}

	url := fmt.Sprintf("%s/rest/api/3/issue/%s/remotelink", c.baseURL, ticketID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating link request: %w", err)
	}
	req.Header.Set("Authorization", c.authHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("linking PR to %s: %w", ticketID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Jira link returned %d for %s: %s", resp.StatusCode, ticketID, string(respBody[:min(len(respBody), 200)]))
	}

	return nil
}

func (c *Client) AddLabel(ticketID string, labels ...string) error {
	adds := make([]map[string]string, len(labels))
	for i, l := range labels {
		adds[i] = map[string]string{"add": l}
	}
	payload := map[string]interface{}{
		"update": map[string]interface{}{
			"labels": adds,
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling labels: %w", err)
	}

	url := fmt.Sprintf("%s/rest/api/3/issue/%s", c.baseURL, ticketID)
	req, err := http.NewRequest("PUT", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating label request: %w", err)
	}
	req.Header.Set("Authorization", c.authHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("adding labels to %s: %w", ticketID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Jira label update returned %d for %s: %s", resp.StatusCode, ticketID, string(respBody[:min(len(respBody), 200)]))
	}

	return nil
}
