package elevator

// Request is sent by agentd.
type Request struct {
	Op       string `json:"op"` // "open"
	MTU      int    `json:"mtu"`
	Instance string `json:"instance"`
	KeepDNS  bool   `json:"keep_dns,omitempty"`  // tun.dns.override_system: false
	FakeOnly bool   `json:"fake_only,omitempty"` // tun.capture: fakeip (no default-route takeover)
}

// Physical describes the network the device's own traffic must use.
type Physical struct {
	Interface string `json:"interface"`
	Index     int    `json:"index"`
	IPv4      string `json:"ipv4,omitempty"`
	IPv6      string `json:"ipv6,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
}

// Response answers a request (with the TUN descriptor attached) or reports a
// network change (Event "network").
type Response struct {
	OK       bool     `json:"ok"`
	Error    string   `json:"error,omitempty"`
	Event    string   `json:"event,omitempty"`
	Name     string   `json:"name,omitempty"`
	MTU      int      `json:"mtu,omitempty"`
	Physical Physical `json:"physical"`
	DNS      []string `json:"dns,omitempty"` // upstream resolvers saved before the takeover
}
