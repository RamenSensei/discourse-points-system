// Package discoursebot is a minimal Discourse Admin API client used to
// publish daily STH posts to a forum topic.
package discoursebot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	Base     string // e.g. "https://forum.example.com"
	APIKey   string
	Username string // typically "system"
	HTTP     *http.Client
}

func New(base, key, user string) *Client {
	if user == "" {
		user = "system"
	}
	return &Client{
		Base:     strings.TrimRight(base, "/"),
		APIKey:   key,
		Username: user,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) do(ctx context.Context, method, path string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Api-Key", c.APIKey)
	req.Header.Set("Api-Username", c.Username)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, string(body))
	}
	if out != nil && len(body) > 0 {
		return json.Unmarshal(body, out)
	}
	return nil
}

type CreateTopicResp struct {
	ID        int    `json:"id"`
	TopicID   int    `json:"topic_id"`
	TopicSlug string `json:"topic_slug"`
}

// CreateTopic creates a new topic with the given title + body. CategoryID is
// optional (0 = use site default).
func (c *Client) CreateTopic(ctx context.Context, title, body string, categoryID int) (*CreateTopicResp, error) {
	form := url.Values{}
	form.Set("title", title)
	form.Set("raw", body)
	if categoryID > 0 {
		form.Set("category", fmt.Sprintf("%d", categoryID))
	}
	var resp CreateTopicResp
	if err := c.do(ctx, "POST", "/posts.json", form, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReplyToTopic appends a post to an existing topic.
func (c *Client) ReplyToTopic(ctx context.Context, topicID int, body string) (*CreateTopicResp, error) {
	form := url.Values{}
	form.Set("topic_id", fmt.Sprintf("%d", topicID))
	form.Set("raw", body)
	var resp CreateTopicResp
	if err := c.do(ctx, "POST", "/posts.json", form, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PinTopic toggles a topic's pin status (admins only).
func (c *Client) PinTopic(ctx context.Context, topicID int, until string) error {
	form := url.Values{}
	form.Set("status", "pinned")
	form.Set("enabled", "true")
	if until != "" {
		form.Set("until", until)
	}
	return c.do(ctx, "PUT", fmt.Sprintf("/t/%d/status.json", topicID), form, nil)
}
