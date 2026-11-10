package control

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	sdkerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
)

// DNSPodClient manages the records that answer ACME DNS-01 challenges in
// DNSPod (Tencent Cloud DNS), through API 3.0 and the official SDK, which
// signs the requests. Zones are the domains of the account (e.g. cs.ac.cn);
// record ids are DNSPod's numeric RecordId.
type DNSPodClient struct {
	SecretID  string
	SecretKey string
	Endpoint  string // default dnspod.tencentcloudapi.com
	Scheme    string // default HTTPS
	PageSize  int    // DescribeDomainList page size; default 3000, the API maximum

	once   sync.Once
	client *dnspod.Client
	err    error
}

// dnspodMinTTL is the lowest TTL every DNSPod plan accepts.
const dnspodMinTTL = 600

func (c *DNSPodClient) api() (*dnspod.Client, error) {
	c.once.Do(func() {
		cpf := profile.NewClientProfile()
		cpf.HttpProfile.Endpoint = "dnspod.tencentcloudapi.com"
		if c.Endpoint != "" {
			cpf.HttpProfile.Endpoint = c.Endpoint
		}
		if c.Scheme != "" {
			cpf.HttpProfile.Scheme = c.Scheme
		}
		cpf.HttpProfile.ReqTimeout = 30
		c.client, c.err = dnspod.NewClient(common.NewCredential(c.SecretID, c.SecretKey), "", cpf)
	})
	return c.client, c.err
}

// dnspodError keeps the action and the API's error code and message.
func dnspodError(action string, err error) error {
	var e *sdkerrors.TencentCloudSDKError
	if errors.As(err, &e) {
		return fmt.Errorf("dnspod %s: %s: %s", action, e.GetCode(), e.GetMessage())
	}
	return fmt.Errorf("dnspod %s: %w", action, err)
}

// ZoneFor returns the longest domain of the account that contains name.
func (c *DNSPodClient) ZoneFor(ctx context.Context, name string) (string, error) {
	cl, err := c.api()
	if err != nil {
		return "", err
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	size := c.PageSize
	if size <= 0 {
		size = 3000
	}
	best := ""
	for offset := 0; ; offset += size {
		req := dnspod.NewDescribeDomainListRequest()
		req.Offset = common.Int64Ptr(int64(offset))
		req.Limit = common.Int64Ptr(int64(size))
		resp, err := cl.DescribeDomainListWithContext(ctx, req)
		if err != nil {
			return "", dnspodError("DescribeDomainList", err)
		}
		if resp.Response == nil {
			return "", errors.New("dnspod DescribeDomainList: empty response")
		}
		page := resp.Response.DomainList
		for _, d := range page {
			if d == nil || d.Name == nil {
				continue
			}
			if z := strings.ToLower(*d.Name); inZone(name, z) && len(z) > len(best) {
				best = z
			}
		}
		total := -1
		if info := resp.Response.DomainCountInfo; info != nil && info.AllTotal != nil {
			total = int(*info.AllTotal)
		}
		if len(page) < size || (total >= 0 && offset+len(page) >= total) {
			break
		}
	}
	if best == "" {
		return "", fmt.Errorf("no DNSPod zone in the account contains %s", name)
	}
	return best, nil
}

// CreateRecord creates r (Name fully qualified) in zone on the default line.
func (c *DNSPodClient) CreateRecord(ctx context.Context, zone string, r DNSRecord) (string, error) {
	sub, err := relativeName(r.Name, zone)
	if err != nil {
		return "", err
	}
	cl, err := c.api()
	if err != nil {
		return "", err
	}
	ttl := uint64(dnspodMinTTL)
	if r.TTL > dnspodMinTTL {
		ttl = uint64(r.TTL)
	}
	req := dnspod.NewCreateRecordRequest()
	req.Domain = common.StringPtr(zone)
	req.SubDomain = common.StringPtr(sub)
	req.RecordType = common.StringPtr(r.Type)
	req.RecordLine = common.StringPtr("默认")
	req.Value = common.StringPtr(r.Content)
	req.TTL = common.Uint64Ptr(ttl)
	resp, err := cl.CreateRecordWithContext(ctx, req)
	if err != nil {
		return "", dnspodError("CreateRecord", err)
	}
	if resp.Response == nil || resp.Response.RecordId == nil {
		return "", errors.New("dnspod CreateRecord: the response has no record id")
	}
	return strconv.FormatUint(*resp.Response.RecordId, 10), nil
}

// DeleteRecord deletes the record with DNSPod id id from zone.
func (c *DNSPodClient) DeleteRecord(ctx context.Context, zone, id string) error {
	n, err := strconv.ParseUint(id, 10, 64)
	if err != nil || n == 0 {
		return fmt.Errorf("dnspod: invalid record id %q", id)
	}
	cl, err := c.api()
	if err != nil {
		return err
	}
	req := dnspod.NewDeleteRecordRequest()
	req.Domain = common.StringPtr(zone)
	req.RecordId = common.Uint64Ptr(n)
	if _, err := cl.DeleteRecordWithContext(ctx, req); err != nil {
		return dnspodError("DeleteRecord", err)
	}
	return nil
}

// inZone reports whether name is zone or below it, comparing whole labels.
func inZone(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// relativeName returns name relative to zone ("@" for the zone itself).
func relativeName(name, zone string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	if name == zone {
		return "@", nil
	}
	if !inZone(name, zone) {
		return "", fmt.Errorf("%s is not in zone %s", name, zone)
	}
	return strings.TrimSuffix(name, "."+zone), nil
}
