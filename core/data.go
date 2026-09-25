package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/jinzhu/gorm"
	"github.com/tredoe/osutil/user/crypt/sha512_crypt"
	"golang.org/x/crypto/bcrypt"
)

// Data is what cocosmail keeps in its database besides settings: domains,
// users, aliases, relay IPs, routes and DKIM keys. It's exported and imported
// with the settings, in the config file.
type Data struct {
	Domains  []DomainData `yaml:"domains,omitempty"`
	Users    []UserData   `yaml:"users,omitempty"`
	Aliases  []AliasData  `yaml:"aliases,omitempty"`
	RelayIPs []string     `yaml:"relay_ips,omitempty"`
	Routes   []RouteData  `yaml:"routes,omitempty"`
	Dkim     []DkimData   `yaml:"dkim,omitempty"`
}

// DomainData is a domain cocosmail accepts mail for. Domain aliases are not
// listed: they come with their alias (an alias without @).
type DomainData struct {
	Name string `yaml:"name"`
	// Local: mail is delivered to mailboxes here, else it's relayed
	Local bool `yaml:"local"`
}

// UserData is a user: a mailbox and/or a login to send mail
type UserData struct {
	Login string `yaml:"login"`
	// Password in clear text, only to import: it's hashed
	Password     string `yaml:"password,omitempty"`
	PasswordHash string `yaml:"password_hash,omitempty"`
	// DovecotHash is the SHA512-crypt hash, for dovecot
	DovecotHash string `yaml:"dovecot_hash,omitempty"`
	Mailbox     bool   `yaml:"mailbox"`
	Relay       bool   `yaml:"relay"`
	Catchall    bool   `yaml:"catchall,omitempty"`
	Quota       string `yaml:"quota,omitempty"`
}

// AliasData is an address alias (sales@example.com) delivered to users of the
// same domain, or a domain alias (example.org) delivered to another domain
type AliasData struct {
	Alias     string   `yaml:"alias"`
	DeliverTo []string `yaml:"deliver_to,omitempty"`
	// Pipe: mail is piped to this command
	Pipe     string `yaml:"pipe,omitempty"`
	MiniList bool   `yaml:"minilist,omitempty"`
}

// IsDomain returns true for a domain alias
func (a AliasData) IsDomain() bool {
	return !strings.Contains(a.Alias, "@")
}

// RouteData is a route for outgoing mail
type RouteData struct {
	Destination string `yaml:"destination"`
	RemoteHost  string `yaml:"remote_host"`
	Port        int    `yaml:"port,omitempty"`
	Priority    int    `yaml:"priority,omitempty"`
	LocalIPs    string `yaml:"local_ips,omitempty"`
	User        string `yaml:"user,omitempty"`
	MailFrom    string `yaml:"mail_from,omitempty"`
	Login       string `yaml:"login,omitempty"`
	Password    string `yaml:"password,omitempty"`
}

// key identifies a route, other fields can change
func (r RouteData) key() string {
	return strings.Join([]string{r.Destination, r.RemoteHost, strconv.Itoa(r.Port), r.LocalIPs, r.User, r.MailFrom}, "|")
}

// String describes the route: example.net via smtp.example.net:587
func (r RouteData) String() string {
	s := r.Destination + " via " + net.JoinHostPort(r.RemoteHost, strconv.Itoa(r.Port))
	if r.User != "" {
		s += " for " + r.User
	}
	if r.MailFrom != "" {
		s += " from " + r.MailFrom
	}
	if r.LocalIPs != "" {
		s += " using " + r.LocalIPs
	}
	return s
}

// DkimData is the DKIM key of a domain
type DkimData struct {
	Domain     string `yaml:"domain"`
	Selector   string `yaml:"selector"`
	PrivateKey string `yaml:"private_key"`
}

// DkimKeyBits is the size of new DKIM keys
const DkimKeyBits = 1024

// Empty returns true if there's no data
func (d *Data) Empty() bool {
	return len(d.Domains)+len(d.Users)+len(d.Aliases)+len(d.RelayIPs)+len(d.Routes)+len(d.Dkim) == 0
}

// RemoveSecrets empties password hashes, route passwords and DKIM keys
func (d *Data) RemoveSecrets() {
	for i := range d.Users {
		d.Users[i].Password, d.Users[i].PasswordHash, d.Users[i].DovecotHash = "", "", ""
	}
	for i := range d.Routes {
		d.Routes[i].Password = ""
	}
	for i := range d.Dkim {
		d.Dkim[i].PrivateKey = ""
	}
}

// Copy returns a deep copy
func (d *Data) Copy() *Data {
	c := &Data{
		Domains:  append([]DomainData(nil), d.Domains...),
		Users:    append([]UserData(nil), d.Users...),
		RelayIPs: append([]string(nil), d.RelayIPs...),
		Routes:   append([]RouteData(nil), d.Routes...),
		Dkim:     append([]DkimData(nil), d.Dkim...),
	}
	for _, a := range d.Aliases {
		a.DeliverTo = append([]string(nil), a.DeliverTo...)
		c.Aliases = append(c.Aliases, a)
	}
	return c
}

// ExportData returns the data in DB, sorted
func ExportData(db *gorm.DB) (*Data, error) {
	d := &Data{}
	var hosts []RcptHost
	if err := db.Find(&hosts).Error; err != nil {
		return nil, err
	}
	for _, h := range hosts {
		if !h.IsAlias {
			d.Domains = append(d.Domains, DomainData{Name: h.Hostname, Local: h.IsLocal})
		}
	}
	var users []User
	if err := db.Find(&users).Error; err != nil {
		return nil, err
	}
	for _, u := range users {
		d.Users = append(d.Users, UserData{Login: u.Login, PasswordHash: u.Passwd, DovecotHash: u.DovePasswd,
			Mailbox: u.HaveMailbox, Relay: u.AuthRelay, Catchall: u.IsCatchall, Quota: u.MailboxQuota})
	}
	var aliases []Alias
	if err := db.Find(&aliases).Error; err != nil {
		return nil, err
	}
	for _, a := range aliases {
		ad := AliasData{Alias: a.Alias, Pipe: a.Pipe, MiniList: a.IsMiniList}
		for _, t := range strings.Split(a.DeliverTo, ";") {
			if t = strings.TrimSpace(t); t != "" {
				ad.DeliverTo = append(ad.DeliverTo, t)
			}
		}
		d.Aliases = append(d.Aliases, ad)
	}
	var ips []RelayIpOk
	if err := db.Find(&ips).Error; err != nil {
		return nil, err
	}
	for _, ip := range ips {
		d.RelayIPs = append(d.RelayIPs, ip.Ip)
	}
	var routes []Route
	if err := db.Find(&routes).Error; err != nil {
		return nil, err
	}
	for _, r := range routes {
		d.Routes = append(d.Routes, RouteData{Destination: r.Host, RemoteHost: r.RemoteHost,
			Port: int(r.RemotePort.Int64), Priority: int(r.Priority.Int64), LocalIPs: r.LocalIp.String,
			User: r.User.String, MailFrom: r.MailFrom.String, Login: r.SmtpAuthLogin.String, Password: r.SmtpAuthPasswd.String})
	}
	var dkims []DkimConfig
	if err := db.Find(&dkims).Error; err != nil {
		return nil, err
	}
	for _, k := range dkims {
		d.Dkim = append(d.Dkim, DkimData{Domain: k.Domain, Selector: k.Selector, PrivateKey: k.PrivKey})
	}
	d.Sort()
	return d, nil
}

// Sort sorts items by name
func (d *Data) Sort() {
	sort.Slice(d.Domains, func(i, j int) bool { return d.Domains[i].Name < d.Domains[j].Name })
	sort.Slice(d.Users, func(i, j int) bool { return d.Users[i].Login < d.Users[j].Login })
	sort.Slice(d.Aliases, func(i, j int) bool { return d.Aliases[i].Alias < d.Aliases[j].Alias })
	sort.Strings(d.RelayIPs)
	sort.Slice(d.Routes, func(i, j int) bool { return d.Routes[i].key() < d.Routes[j].key() })
	sort.Slice(d.Dkim, func(i, j int) bool { return d.Dkim[i].Domain < d.Dkim[j].Domain })
}

// normalize lowercases names and canonicalizes IPs, and hashes clear text
// passwords
func (d *Data) normalize() error {
	for i := range d.Domains {
		d.Domains[i].Name = strings.ToLower(strings.TrimSpace(d.Domains[i].Name))
	}
	for i := range d.Users {
		u := &d.Users[i]
		u.Login = strings.ToLower(strings.TrimSpace(u.Login))
		if u.Password != "" {
			hash, doveHash, err := HashPassword(u.Password)
			if err != nil {
				return errors.New("user " + u.Login + ": " + err.Error())
			}
			u.PasswordHash, u.DovecotHash, u.Password = hash, doveHash, ""
		}
	}
	for i := range d.Aliases {
		a := &d.Aliases[i]
		a.Alias = strings.ToLower(strings.TrimSpace(a.Alias))
		for j := range a.DeliverTo {
			a.DeliverTo[j] = strings.ToLower(strings.TrimSpace(a.DeliverTo[j]))
		}
		a.Pipe = strings.TrimSpace(a.Pipe)
	}
	for i, ip := range d.RelayIPs {
		if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
			d.RelayIPs[i] = parsed.String()
		}
	}
	for i := range d.Routes {
		r := &d.Routes[i]
		r.Destination = strings.ToLower(strings.TrimSpace(r.Destination))
		r.RemoteHost = strings.ToLower(strings.TrimSpace(r.RemoteHost))
		r.MailFrom = strings.ToLower(strings.TrimSpace(r.MailFrom))
		if r.Port == 0 {
			r.Port = 25
		}
	}
	for i := range d.Dkim {
		d.Dkim[i].Domain = strings.ToLower(strings.TrimSpace(d.Dkim[i].Domain))
	}
	d.Sort()
	return nil
}

// keepPasswords keeps the hashes of cur for clear text passwords that match
// them, so importing the same file again changes nothing
func (d *Data) keepPasswords(cur *Data) {
	for i := range d.Users {
		u := &d.Users[i]
		if u.Password == "" {
			continue
		}
		login := strings.ToLower(strings.TrimSpace(u.Login))
		for _, c := range cur.Users {
			if c.Login == login && c.DovecotHash != "" && bcrypt.CompareHashAndPassword([]byte(c.PasswordHash), []byte(u.Password)) == nil {
				u.Password, u.PasswordHash, u.DovecotHash = "", c.PasswordHash, c.DovecotHash
			}
		}
	}
}

// DataEmpty returns true if there's no data in DB
func DataEmpty(db *gorm.DB) (bool, error) {
	for _, model := range []interface{}{&RcptHost{}, &User{}, &Alias{}, &RelayIpOk{}, &Route{}, &DkimConfig{}} {
		var n int
		if err := db.Model(model).Count(&n).Error; err != nil {
			return false, err
		}
		if n > 0 {
			return false, nil
		}
	}
	return true, nil
}

// HashPassword returns the bcrypt hash of password, and its SHA512-crypt hash
// for dovecot
func HashPassword(password string) (hash, dovecotHash string, err error) {
	if len(password) < 6 {
		return "", "", errors.New("password must be at least 6 chars length")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", "", err
	}
	salt, err := NewUUID()
	if err != nil {
		return "", "", err
	}
	dovecotHash, err = sha512_crypt.New().Generate([]byte(password), []byte("$6$"+salt[:16]))
	return string(b), dovecotHash, err
}

// ValidateData checks data as a whole: names, and that what's referenced
// exists (users' domains, aliases' users...). It returns all errors.
func ValidateData(d *Data) (errs []error) {
	fail := func(format string, a ...interface{}) { errs = append(errs, fmt.Errorf(format, a...)) }
	domains := make(map[string]DomainData)
	for _, dom := range d.Domains {
		if !validDomain(dom.Name) {
			fail("domain %q is not a valid domain name", dom.Name)
		}
		if _, ok := domains[dom.Name]; ok {
			fail("domain %s is listed twice", dom.Name)
		}
		domains[dom.Name] = dom
	}
	users := make(map[string]UserData)
	catchall := make(map[string]string)
	for _, u := range d.Users {
		if len(u.Login) < 4 || len(u.Login) > 256 || strings.ContainsAny(u.Login, " ;:") {
			fail("user %q: the login must have 4 to 256 chars, without spaces, ; or :", u.Login)
			continue
		}
		if _, ok := users[u.Login]; ok {
			fail("user %s is listed twice", u.Login)
		}
		users[u.Login] = u
		if !strings.HasPrefix(u.PasswordHash, "$2") {
			fail("user %s: a password is needed", u.Login)
		}
		if u.Catchall && !u.Mailbox {
			fail("user %s: a catch-all needs a mailbox", u.Login)
		}
		if !u.Mailbox {
			continue
		}
		// a mailbox is an email address in a local domain
		t := strings.Split(u.Login, "@")
		if len(t) != 2 || t[0] == "" || !validDomain(t[1]) {
			fail("user %s: the login of a mailbox must be an email address", u.Login)
			continue
		}
		if dom, ok := domains[t[1]]; !ok || !dom.Local {
			fail("user %s: %s must be a local domain", u.Login, t[1])
		}
		if u.Catchall {
			if other, ok := catchall[t[1]]; ok {
				fail("users %s and %s are both catch-all of %s", other, u.Login, t[1])
			}
			catchall[t[1]] = u.Login
		}
	}
	aliases := make(map[string]bool)
	for _, a := range d.Aliases {
		if aliases[a.Alias] {
			fail("alias %s is listed twice", a.Alias)
		}
		aliases[a.Alias] = true
		if len(a.DeliverTo) == 0 && a.Pipe == "" {
			fail("alias %s: it needs recipients or a pipe command", a.Alias)
		}
		if a.IsDomain() {
			if !validDomain(a.Alias) {
				fail("domain alias %q is not a valid domain name", a.Alias)
			}
			if _, ok := domains[a.Alias]; ok {
				fail("domain alias %s is also a domain", a.Alias)
			}
			if a.MiniList {
				fail("domain alias %s can't be a mini list", a.Alias)
			}
			if len(a.DeliverTo) > 1 {
				fail("domain alias %s can point to one domain only", a.Alias)
			}
			for _, to := range a.DeliverTo {
				if dom, ok := domains[to]; !ok || !dom.Local {
					fail("domain alias %s: %s must be a local domain", a.Alias, to)
				}
			}
			continue
		}
		t := strings.Split(a.Alias, "@")
		if len(t) != 2 || t[0] == "" {
			fail("alias %q must be an email address or a domain", a.Alias)
			continue
		}
		if dom, ok := domains[t[1]]; !ok || !dom.Local {
			fail("alias %s: %s must be a local domain", a.Alias, t[1])
		}
		if _, ok := users[a.Alias]; ok {
			fail("alias %s is also a user", a.Alias)
		}
		for _, to := range a.DeliverTo {
			u, ok := users[to]
			switch {
			case !ok:
				fail("alias %s: user %s doesn't exist", a.Alias, to)
			case !u.Mailbox:
				fail("alias %s: user %s has no mailbox", a.Alias, to)
			case !strings.HasSuffix(to, "@"+t[1]):
				fail("alias %s: %s is not in the same domain", a.Alias, to)
			}
		}
	}
	for _, ip := range d.RelayIPs {
		if net.ParseIP(ip) == nil {
			fail("relay IP %q is not an IP address", ip)
		}
	}
	for _, r := range d.Routes {
		if r.Destination == "" || r.RemoteHost == "" {
			fail("route %s -> %s: destination and remote host are needed", r.Destination, r.RemoteHost)
		}
		if r.Port < 1 || r.Port > 65535 {
			fail("route %s: port %d is not valid", r.Destination, r.Port)
		}
		if r.LocalIPs != "" {
			if err := validateLocalIps(r.LocalIPs); err != nil {
				fail("route %s: local IPs: %v", r.Destination, err)
			}
		}
	}
	dkims := make(map[string]bool)
	for _, k := range d.Dkim {
		if dkims[k.Domain] {
			fail("DKIM key of %s is listed twice", k.Domain)
		}
		dkims[k.Domain] = true
		if !validDomain(k.Domain) {
			fail("DKIM: %q is not a valid domain name", k.Domain)
		}
		if k.Selector == "" || strings.ContainsAny(k.Selector, " .;") {
			fail("DKIM of %s: the selector must be a name without spaces, dots or ;", k.Domain)
		}
		if _, err := DkimPublicKey(k.PrivateKey); err != nil {
			fail("DKIM of %s: %v", k.Domain, err)
		}
	}
	return errs
}

func validDomain(name string) bool {
	return name != "" && !strings.ContainsAny(name, " @;:/\\,") && !strings.HasPrefix(name, ".") && !strings.HasSuffix(name, ".")
}

// NewDkimKey returns a new DKIM private key, PEM encoded
func NewDkimKey() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, DkimKeyBits)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil
}

// DkimPublicKey returns the public key of a PEM private key, as in the DNS record
func DkimPublicKey(privateKey string) (string, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return "", errors.New("the private key is not in PEM format")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", errors.New("the private key is not an RSA key: " + err.Error())
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	t := strings.Split(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), "\n")
	return strings.Join(t[1:len(t)-2], ""), nil
}

// DkimDNSRecord returns the name and the value of the DNS TXT record of a DKIM key
func DkimDNSRecord(k DkimData) (name, value string, err error) {
	pub, err := DkimPublicKey(k.PrivateKey)
	if err != nil {
		return "", "", err
	}
	return k.Selector + "._domainkey." + k.Domain, "v=DKIM1;k=rsa;s=email;h=sha256;p=" + pub, nil
}

// DiffData describes the changes from cur to next, one line each
func DiffData(cur, next *Data) (changes []string) {
	diff := func(kind string, curKeys, nextKeys []string, curItems, nextItems map[string]interface{}) {
		for _, k := range nextKeys {
			if c, ok := curItems[k]; !ok {
				changes = append(changes, "add "+kind+" "+k)
			} else if !reflect.DeepEqual(c, nextItems[k]) {
				changes = append(changes, "change "+kind+" "+k)
			}
		}
		for _, k := range curKeys {
			if _, ok := nextItems[k]; !ok {
				changes = append(changes, "delete "+kind+" "+k)
			}
		}
	}
	index := func(n int, key func(i int) string, item func(i int) interface{}) ([]string, map[string]interface{}) {
		keys, items := make([]string, 0, n), make(map[string]interface{}, n)
		for i := 0; i < n; i++ {
			keys = append(keys, key(i))
			items[key(i)] = item(i)
		}
		return keys, items
	}
	ck, ci := index(len(cur.Domains), func(i int) string { return cur.Domains[i].Name }, func(i int) interface{} { return cur.Domains[i] })
	nk, ni := index(len(next.Domains), func(i int) string { return next.Domains[i].Name }, func(i int) interface{} { return next.Domains[i] })
	diff("domain", ck, nk, ci, ni)
	ck, ci = index(len(cur.Users), func(i int) string { return cur.Users[i].Login }, func(i int) interface{} { return cur.Users[i] })
	nk, ni = index(len(next.Users), func(i int) string { return next.Users[i].Login }, func(i int) interface{} { return next.Users[i] })
	diff("user", ck, nk, ci, ni)
	ck, ci = index(len(cur.Aliases), func(i int) string { return cur.Aliases[i].Alias }, func(i int) interface{} { return cur.Aliases[i] })
	nk, ni = index(len(next.Aliases), func(i int) string { return next.Aliases[i].Alias }, func(i int) interface{} { return next.Aliases[i] })
	diff("alias", ck, nk, ci, ni)
	ck, ci = index(len(cur.RelayIPs), func(i int) string { return cur.RelayIPs[i] }, func(i int) interface{} { return cur.RelayIPs[i] })
	nk, ni = index(len(next.RelayIPs), func(i int) string { return next.RelayIPs[i] }, func(i int) interface{} { return next.RelayIPs[i] })
	diff("relay IP", ck, nk, ci, ni)
	ck, ci = index(len(cur.Routes), func(i int) string { return cur.Routes[i].String() }, func(i int) interface{} { return cur.Routes[i] })
	nk, ni = index(len(next.Routes), func(i int) string { return next.Routes[i].String() }, func(i int) interface{} { return next.Routes[i] })
	diff("route", ck, nk, ci, ni)
	ck, ci = index(len(cur.Dkim), func(i int) string { return cur.Dkim[i].Domain }, func(i int) interface{} { return cur.Dkim[i] })
	nk, ni = index(len(next.Dkim), func(i int) string { return next.Dkim[i].Domain }, func(i int) interface{} { return next.Dkim[i] })
	diff("DKIM key", ck, nk, ci, ni)
	return changes
}

// mergeData returns cur with in: items of in replace the ones with the same
// key, and with replace, items not in in are removed. Empty secrets of in
// (exported with --no-secrets) keep the current ones.
func mergeData(cur, in *Data, replace bool) *Data {
	in = in.Copy()
	for i := range in.Users {
		x := &in.Users[i]
		for _, u := range cur.Users {
			if u.Login == x.Login && x.PasswordHash == "" {
				x.PasswordHash, x.DovecotHash = u.PasswordHash, u.DovecotHash
			}
		}
	}
	for i := range in.Routes {
		x := &in.Routes[i]
		for _, r := range cur.Routes {
			if r.key() == x.key() && x.Login != "" && x.Password == "" {
				x.Password = r.Password
			}
		}
	}
	for i := range in.Dkim {
		x := &in.Dkim[i]
		for _, k := range cur.Dkim {
			if k.Domain == x.Domain && x.PrivateKey == "" {
				x.PrivateKey = k.PrivateKey
			}
		}
	}
	if replace {
		in.Sort()
		return in
	}
	out := cur.Copy()
	for _, x := range in.Domains {
		out.Domains = upsert(out.Domains, x, func(a DomainData) bool { return a.Name == x.Name })
	}
	for _, x := range in.Users {
		out.Users = upsert(out.Users, x, func(a UserData) bool { return a.Login == x.Login })
	}
	for _, x := range in.Aliases {
		out.Aliases = upsert(out.Aliases, x, func(a AliasData) bool { return a.Alias == x.Alias })
	}
	for _, x := range in.RelayIPs {
		out.RelayIPs = upsert(out.RelayIPs, x, func(a string) bool { return a == x })
	}
	for _, x := range in.Routes {
		out.Routes = upsert(out.Routes, x, func(a RouteData) bool { return a.key() == x.key() })
	}
	for _, x := range in.Dkim {
		out.Dkim = upsert(out.Dkim, x, func(a DkimData) bool { return a.Domain == x.Domain })
	}
	out.Sort()
	return out
}

func upsert[T any](items []T, x T, same func(T) bool) []T {
	for i := range items {
		if same(items[i]) {
			items[i] = x
			return items
		}
	}
	return append(items, x)
}

// ImportData makes the data in DB the data of in: items are added or
// replaced, and with replace, items not in in are deleted. The result is
// checked as a whole before anything is written. It returns the changes;
// with dryRun, nothing is written.
func ImportData(db *gorm.DB, in *Data, replace, dryRun bool) (changes []string, err error) {
	cur, err := ExportData(db)
	if err != nil {
		return nil, err
	}
	in = in.Copy()
	in.keepPasswords(cur)
	if err := in.normalize(); err != nil {
		return nil, err
	}
	return applyData(db, cur, mergeData(cur, in, replace), dryRun)
}

// EditData applies to DB the changes from old to new: what was added,
// changed or deleted in new. Other changes made in DB since old was
// exported are kept.
func EditData(db *gorm.DB, old, new *Data) (changes []string, err error) {
	cur, err := ExportData(db)
	if err != nil {
		return nil, err
	}
	new = new.Copy()
	if err := new.normalize(); err != nil {
		return nil, err
	}
	return applyData(db, cur, MergeEdit(cur, old, new), false)
}

// applyData checks next and makes it the data in DB, cur is the data in DB
func applyData(db *gorm.DB, cur, next *Data, dryRun bool) (changes []string, err error) {
	if errs := ValidateData(next); len(errs) > 0 {
		return nil, joinErrors(errs)
	}
	changes = DiffData(cur, next)
	if dryRun || len(changes) == 0 {
		return changes, nil
	}
	if Cfg == nil {
		// users' homes depend on settings
		if err := loadDBSettings(db); err != nil {
			return nil, err
		}
	}
	tx := db.Begin()
	if err := writeData(tx, cur, next); err != nil {
		tx.Rollback()
		return nil, err
	}
	return changes, tx.Commit().Error
}

// MergeEdit returns base with the changes from old to new: items added or
// changed in new are set, items of old not in new are removed
func MergeEdit(base, old, new *Data) *Data {
	out := &Data{
		Domains:  mergeEdit(base.Domains, old.Domains, new.Domains, func(x DomainData) string { return x.Name }),
		Users:    mergeEdit(base.Users, old.Users, new.Users, func(x UserData) string { return x.Login }),
		Aliases:  mergeEdit(base.Aliases, old.Aliases, new.Aliases, func(x AliasData) string { return x.Alias }),
		RelayIPs: mergeEdit(base.RelayIPs, old.RelayIPs, new.RelayIPs, func(x string) string { return x }),
		Routes:   mergeEdit(base.Routes, old.Routes, new.Routes, func(x RouteData) string { return x.key() }),
		Dkim:     mergeEdit(base.Dkim, old.Dkim, new.Dkim, func(x DkimData) string { return x.Domain }),
	}
	out.Sort()
	return out
}

func mergeEdit[T any](base, old, new []T, key func(T) string) []T {
	oldItems := make(map[string]T, len(old))
	for _, x := range old {
		oldItems[key(x)] = x
	}
	newKeys := make(map[string]bool, len(new))
	out := append([]T(nil), base...)
	for _, x := range new {
		k := key(x)
		newKeys[k] = true
		if o, ok := oldItems[k]; !ok || !reflect.DeepEqual(o, x) {
			out = upsert(out, x, func(a T) bool { return key(a) == k })
		}
	}
	for k := range oldItems {
		if !newKeys[k] {
			kept := out[:0]
			for _, x := range out {
				if key(x) != k {
					kept = append(kept, x)
				}
			}
			out = kept
		}
	}
	return out
}

// writeData changes DB from cur to next
func writeData(tx *gorm.DB, cur, next *Data) error {
	// domains, and the domains of domain aliases
	hosts := make(map[string]RcptHost)
	for _, dom := range next.Domains {
		hosts[dom.Name] = RcptHost{Hostname: dom.Name, IsLocal: dom.Local}
	}
	for _, a := range next.Aliases {
		if a.IsDomain() {
			hosts[a.Alias] = RcptHost{Hostname: a.Alias, IsLocal: true, IsAlias: true}
		}
	}
	var curHosts []RcptHost
	if err := tx.Find(&curHosts).Error; err != nil {
		return err
	}
	for _, h := range curHosts {
		if want, ok := hosts[h.Hostname]; !ok {
			if err := tx.Delete(&h).Error; err != nil {
				return err
			}
		} else if want.IsLocal != h.IsLocal || want.IsAlias != h.IsAlias {
			h.IsLocal, h.IsAlias = want.IsLocal, want.IsAlias
			if err := tx.Save(&h).Error; err != nil {
				return err
			}
		}
		delete(hosts, h.Hostname)
	}
	for _, h := range hosts {
		h := h
		if err := tx.Create(&h).Error; err != nil {
			return err
		}
	}

	// users
	var curUsers []User
	if err := tx.Find(&curUsers).Error; err != nil {
		return err
	}
	byLogin := make(map[string]User)
	for _, u := range curUsers {
		byLogin[u.Login] = u
	}
	for _, nu := range next.Users {
		u, ok := byLogin[nu.Login]
		if !ok {
			u = User{Login: nu.Login, Active: "Y"}
		}
		if t := strings.Split(nu.Login, "@"); nu.Mailbox && u.Home == "" && len(t) == 2 {
			u.Home = userHome(t[0], t[1])
		}
		u.Passwd, u.DovePasswd = nu.PasswordHash, nu.DovecotHash
		u.HaveMailbox, u.AuthRelay, u.IsCatchall, u.MailboxQuota = nu.Mailbox, nu.Relay, nu.Catchall, nu.Quota
		if err := tx.Save(&u).Error; err != nil {
			return err
		}
		delete(byLogin, nu.Login)
	}
	for _, u := range byLogin {
		u := u
		if err := tx.Delete(&u).Error; err != nil {
			return err
		}
	}

	// aliases
	var curAliases []Alias
	if err := tx.Find(&curAliases).Error; err != nil {
		return err
	}
	byAlias := make(map[string]Alias)
	for _, a := range curAliases {
		byAlias[a.Alias] = a
	}
	for _, na := range next.Aliases {
		a := byAlias[na.Alias]
		a.Alias, a.DeliverTo, a.Pipe = na.Alias, strings.Join(na.DeliverTo, ";"), na.Pipe
		a.IsDomAlias, a.IsMiniList = na.IsDomain(), na.MiniList
		if err := tx.Save(&a).Error; err != nil {
			return err
		}
		delete(byAlias, na.Alias)
	}
	for _, a := range byAlias {
		a := a
		if err := tx.Delete(&a).Error; err != nil {
			return err
		}
	}

	// relay IPs
	if err := tx.Delete(RelayIpOk{}).Error; err != nil {
		return err
	}
	for _, ip := range next.RelayIPs {
		if err := tx.Create(&RelayIpOk{Ip: ip}).Error; err != nil {
			return err
		}
	}

	// routes
	if err := tx.Delete(Route{}).Error; err != nil {
		return err
	}
	for _, r := range next.Routes {
		route := Route{Host: r.Destination, RemoteHost: r.RemoteHost}
		_ = route.RemotePort.Scan(int64(r.Port))
		_ = route.Priority.Scan(int64(r.Priority))
		for _, f := range []struct {
			dst *string
			ok  *bool
			v   string
		}{
			{&route.LocalIp.String, &route.LocalIp.Valid, r.LocalIPs},
			{&route.User.String, &route.User.Valid, r.User},
			{&route.MailFrom.String, &route.MailFrom.Valid, r.MailFrom},
			{&route.SmtpAuthLogin.String, &route.SmtpAuthLogin.Valid, r.Login},
			{&route.SmtpAuthPasswd.String, &route.SmtpAuthPasswd.Valid, r.Password},
		} {
			*f.dst, *f.ok = f.v, f.v != ""
		}
		if err := tx.Create(&route).Error; err != nil {
			return err
		}
	}

	// DKIM
	if err := tx.Delete(DkimConfig{}).Error; err != nil {
		return err
	}
	for _, k := range next.Dkim {
		pub, err := DkimPublicKey(k.PrivateKey)
		if err != nil {
			return err
		}
		if err := tx.Create(&DkimConfig{Domain: k.Domain, Selector: k.Selector, PrivKey: k.PrivateKey, PubKey: pub}).Error; err != nil {
			return err
		}
	}
	return nil
}
