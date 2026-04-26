package jira

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

const (
	defaultBaseURL = "https://redhat.atlassian.net"
	defaultEmail   = "oraz@redhat.com"
)

var (
	cvePattern   = regexp.MustCompile(`CVE-\d{4}-\d+`)
	goPackageRe  = regexp.MustCompile(`(?i)(golang\.org/x/\S+|github\.com/[\w\-]+/[\w\-]+(?:/\S+)?|google\.golang\.org/\S+|gopkg\.in/\S+)`)
	stdlibPkgRe  = regexp.MustCompile(`(?i)\b(crypto/\w+|net/\w+|encoding/\w+|archive/\w+|compress/\w+|html/\w+|text/\w+|math/\w+|os/\w+|path/\w+|regexp|database/\w+|image/\w+)\b`)
)

type Client struct {
	baseURL    string
	authHeader string
	httpClient *http.Client
}

func NewClient() (*Client, error) {
	token := os.Getenv("JIRA_API_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("JIRA_API_TOKEN environment variable is required")
	}

	email := os.Getenv("JIRA_EMAIL")
	if email == "" {
		email = defaultEmail
	}

	baseURL := os.Getenv("JIRA_BASE_URL")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	creds := base64.StdEncoding.EncodeToString([]byte(email + ":" + token))

	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		authHeader: "Basic " + creds,
		httpClient: &http.Client{},
	}, nil
}

func (c *Client) BaseURL() string {
	return c.baseURL
}

var (
	versionBracketRe = regexp.MustCompile(`\[(\w+)-(\d+\.\d+)\]`)
	psComponentRe    = regexp.MustCompile(`pscomponent:(.+)`)
)

type TicketInfo struct {
	Key              string
	Summary          string
	CVEID            string
	Component        string
	ImageName        string
	FixVersions      []string
	AffectsVersions  []string
	OperatorVersion  string
	Status           string
	Labels           []string
	Reporter         string
	Assignee         string
	DueDate          string
	JiraPriority     string
}

func (c *Client) FetchTicket(ticketID string) (*TicketInfo, error) {
	url := fmt.Sprintf("%s/rest/api/3/issue/%s", c.baseURL, ticketID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", c.authHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching ticket %s: %w", ticketID, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Jira API returned %d for %s: %s", resp.StatusCode, ticketID, string(body[:min(len(body), 200)]))
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing ticket JSON: %w", err)
	}

	return parseTicket(raw)
}

func (c *Client) SearchTickets(jql string) ([]TicketInfo, error) {
	url := fmt.Sprintf("%s/rest/api/3/search/jql?jql=%s&maxResults=50&fields=key,summary,status,components,fixVersions,versions,labels,description,reporter,assignee,duedate,priority",
		c.baseURL, encode(jql))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating search request: %w", err)
	}
	req.Header.Set("Authorization", c.authHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("searching tickets: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading search response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Jira search returned %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}

	var result struct {
		Issues []map[string]interface{} `json:"issues"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing search results: %w", err)
	}

	var tickets []TicketInfo
	for _, issue := range result.Issues {
		t, err := parseTicket(issue)
		if err != nil {
			continue
		}
		tickets = append(tickets, *t)
	}

	return tickets, nil
}

func encode(s string) string {
	replacer := strings.NewReplacer(
		" ", "%20",
		"=", "%3D",
		"\"", "%22",
		"(", "%28",
		")", "%29",
		"!", "%21",
	)
	return replacer.Replace(s)
}

func parseTicket(raw map[string]interface{}) (*TicketInfo, error) {
	info := &TicketInfo{}

	info.Key = getString(raw, "key")

	fields, _ := raw["fields"].(map[string]interface{})
	if fields == nil {
		return nil, fmt.Errorf("no fields in ticket data")
	}

	info.Summary = getString(fields, "summary")
	info.Status = getNestedString(fields, "status", "name")

	info.CVEID = getString(fields, "customfield_10667")
	if info.CVEID == "" {
		info.CVEID = extractCVEID(info.Summary)
	}
	if info.CVEID == "" {
		info.CVEID = extractCVEFromDescription(fields)
	}

	if m := versionBracketRe.FindStringSubmatch(info.Summary); len(m) == 3 {
		info.OperatorVersion = m[2]
	}

	if components, ok := fields["components"].([]interface{}); ok {
		for _, c := range components {
			if cm, ok := c.(map[string]interface{}); ok {
				if name := getString(cm, "name"); name != "" {
					if info.Component == "" {
						info.Component = name
					}
				}
			}
		}
	}

	if fixVers, ok := fields["fixVersions"].([]interface{}); ok {
		for _, fv := range fixVers {
			if fvm, ok := fv.(map[string]interface{}); ok {
				if name := getString(fvm, "name"); name != "" {
					info.FixVersions = append(info.FixVersions, name)
				}
			}
		}
	}

	if versions, ok := fields["versions"].([]interface{}); ok {
		for _, v := range versions {
			if vm, ok := v.(map[string]interface{}); ok {
				if name := getString(vm, "name"); name != "" {
					info.AffectsVersions = append(info.AffectsVersions, name)
				}
			}
		}
	}

	if labels, ok := fields["labels"].([]interface{}); ok {
		for _, l := range labels {
			if ls, ok := l.(string); ok {
				info.Labels = append(info.Labels, ls)
			}
		}
	}

	info.Reporter = getNestedString(fields, "reporter", "displayName")
	info.Assignee = getNestedString(fields, "assignee", "displayName")
	info.DueDate = getString(fields, "duedate")
	info.JiraPriority = getNestedString(fields, "priority", "name")

	info.ImageName = extractImageName(info.Summary, info.Labels)

	return info, nil
}

func extractCVEID(text string) string {
	return cvePattern.FindString(text)
}

func extractCVEFromDescription(fields map[string]interface{}) string {
	desc, ok := fields["description"].(map[string]interface{})
	if !ok {
		return ""
	}

	b, err := json.Marshal(desc)
	if err != nil {
		return ""
	}

	return cvePattern.FindString(string(b))
}

func extractImageName(summary string, labels []string) string {
	for _, label := range labels {
		if m := psComponentRe.FindStringSubmatch(label); len(m) == 2 {
			return m[1]
		}
	}

	parts := strings.SplitN(summary, ":", 2)
	if len(parts) == 2 {
		afterCVE := strings.TrimSpace(strings.TrimPrefix(parts[0], extractCVEID(parts[0])))
		afterCVE = strings.TrimSpace(afterCVE)
		if afterCVE != "" {
			return afterCVE
		}
	}

	return ""
}

func ExtractGoPackage(text string) string {
	if m := goPackageRe.FindString(text); m != "" {
		return strings.TrimRight(m, ".,;:)")
	}
	if m := stdlibPkgRe.FindString(text); m != "" {
		return strings.TrimRight(m, ".,;:)")
	}
	return ""
}

func getString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func getNestedString(m map[string]interface{}, keys ...string) string {
	current := m
	for i, key := range keys {
		if i == len(keys)-1 {
			return getString(current, key)
		}
		next, ok := current[key].(map[string]interface{})
		if !ok {
			return ""
		}
		current = next
	}
	return ""
}
