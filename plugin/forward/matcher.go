package forward

import (
	"bufio"
	"fmt"
	"os"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type Matcher interface {
	Match(name string) bool
}

type SingleNameMatcher struct {
	name string
}

func NewSingleNameMatcher(name string) (*SingleNameMatcher, error) {
	parsed := plugin.Host(name).NormalizeExact()
	if len(parsed) == 0 {
		return nil, fmt.Errorf("invalid domain name %s", name)
	}
	return &SingleNameMatcher{parsed[0]}, nil
}

func (m *SingleNameMatcher) Match(name string) bool {
	return plugin.Name(m.name).Matches(name)
}

type MultiNameMatcher struct {
	zones map[string]struct{}
}

func NewMatcherFromFile(path string) (*MultiNameMatcher, error) {
	m := new(MultiNameMatcher)
	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m.zones = make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		zones := plugin.Host(scanner.Text()).NormalizeExact()
		m.zones[zones[0]] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *MultiNameMatcher) Match(name string) bool {
	var (
		offset int
		end    bool
	)
	for !end {
		cur := name[offset:]
		if _, ok := m.zones[cur]; ok {
			return true
		}
		offset, end = dns.NextLabel(name, offset)
	}
	return false
}
