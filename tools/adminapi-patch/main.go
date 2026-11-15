// Command adminapi-patch applies the small source-compatibility layer that is
// intentionally kept in the checked-in Go client while the HTTP contract uses
// UUID resource paths. It runs after oapi-codegen so `make gen` is reproducible.
package main

import (
	"fmt"
	"go/format"
	"os"
	"strings"
)

const file = "internal/adminapi/api.gen.go"

func main() {
	b, err := os.ReadFile(file)
	if err != nil { panic(err) }
	s := string(b)
	s = strings.Replace(s, "type Uuid = openapi_types.UUID", "type Uuid = string", 1)
	s = strings.Replace(s, "JoinLink *string `json:\"join_link,omitempty\"`", "JoinLink string `json:\"join_link,omitempty\"`", 1)
	s = strings.Replace(s, "BaseDomain       *string   `json:\"base_domain,omitempty\"`", "BaseDomain       string    `json:\"base_domain,omitempty\"`", 1)

	s = addField(s, "type InstanceDomain struct {", "\n\tName   string `json:\"name,omitempty\"`", "\n\tId     *Uuid  `json:\"id,omitempty\"`")
	s = addField(s, "type Workspace struct {", "\n\t// Relay and Cert are retained for source compatibility with the v0.30 client.\n\tRelay string `json:\"relay,omitempty\"`\n\tCert  *Cert  `json:\"cert,omitempty\"`", "\n\tStatus        WorkspaceStatus `json:\"status\"`")
	s = addField(s, "type WorkspaceCreate struct {", "\n\t// BaseDomain was accepted by the pre-UUID API. New clients use DomainId.\n\tBaseDomain *string `json:\"base_domain,omitempty\"`", "\n\tName Label `json:\"name\"`")
	s = addField(s, "type WorkspaceMember struct {", "\n\tSubject string `json:\"subject,omitempty\"`", "\n\tUserId Uuid `json:\"user_id\"`")
	s = addField(s, "type WorkspaceMemberWrite struct {", "\n\tSubject string `json:\"subject,omitempty\"`", "\n\tUserId Uuid `json:\"user_id\"`")

	out, err := format.Source([]byte(s))
	if err != nil { panic(fmt.Errorf("format generated admin API: %w", err)) }
	if err := os.WriteFile(file, out, 0o644); err != nil { panic(err) }
}

func addField(s, typeDecl, field, after string) string {
	start := strings.Index(s, typeDecl)
	if start < 0 { return s }
	end := strings.Index(s[start:], "\n}")
	if end < 0 { return s }
	end += start
	block := s[start:end]
	if strings.Contains(block, strings.TrimSpace(field)) { return s }
	i := strings.Index(block, after)
	if i < 0 { return s }
	i += start + len(after)
	return s[:i] + field + s[i:]
}
