// Command protonvpn-profiles creates macOS/iOS profile with ProtonVPN IKEv2
// profiles from zip file containing OpenVPN configuration.
//
// Go to your ProtonVPN account, under Account section copy your username and
// password from OpenVPN/IKEv2 Username/Password fields. Under Downloads section
// use Download All Configurations in country or server configs, this will give
// you single zip file with OpenVPN profiles.
//
// Run:
//
//	protonvpn-profiles -zip ProtonVPN_server_configs.zip \
//		-user $USER -pass $PASSWORD
//
// You can also limit what configurations to import and set single server as
// on-demand VPN connection:
//
//	protonvpn-profiles -zip ProtonVPN_server_configs.zip \
//		-user $USER -pass $PASSWORD \
//		-match '^us-.*\.protonvpn\.com$' \
//		-ondemand us-ca-01.protonvpn.com
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/artyom/autoflags"
	"github.com/artyom/ping"
	"golang.org/x/sync/errgroup"
)

const certIssuer = "ProtonVPN Root CA"
const maxProfiles = 46

func main() {
	args := runArgs{
		Regex: `^.*\.protonvpn\.com$`,
		Out:   "ProtonVPN.mobileconfig",
	}
	autoflags.Parse(&args)
	if err := run(args); err != nil {
		log.Fatal(err)
	}
}

type runArgs struct {
	Username  string `flag:"user,username"`
	Password  string `flag:"pass,password"`
	File      string `flag:"zip,path to zipfile with ProtonVPN profiles"`
	Out       string `flag:"out,path to output file, leave empty for stdout"`
	Regex     string `flag:"match,regex pattern to filter profiles by name"`
	PrintOnly bool   `flag:"print,only print profiles matched by regexp along with their endpoints"`
	Ondemand  string `flag:"ondemand,optional profile name that should have on-demand enabled"`
}

func run(args runArgs) error {
	if !args.PrintOnly && (args.Username == "" || args.Password == "") {
		return fmt.Errorf("username or password can only be empty in print mode")
	}
	re, err := regexp.Compile(args.Regex)
	if err != nil {
		return err
	}
	rd, err := zip.OpenReader(args.File)
	if err != nil {
		return err
	}
	defer rd.Close()
	var ca *pem.Block
	profiles := make([]profile, 0, len(rd.File))
	for _, f := range rd.File {
		if !strings.HasSuffix(f.Name, ".ovpn") {
			continue
		}
		name := nameFromFile(f.Name)
		if !re.MatchString(name) {
			continue
		}
		addr, err := remoteAddress(f.Open)
		if err != nil {
			return err
		}
		profiles = append(profiles, profile{Name: name, Addr: addr, Ondemand: name == args.Ondemand})
		if ca == nil {
			if ca, err = readCertificate(f.Open); err != nil {
				return err
			}
			c, err := x509.ParseCertificate(ca.Bytes)
			if err != nil {
				return err
			}
			if c.Issuer.CommonName != certIssuer {
				return fmt.Errorf("unexpected certificate issuer, want %q, got %q", certIssuer, c.Issuer.CommonName)
			}
		}
	}
	if len(profiles) == 0 || ca == nil {
		return fmt.Errorf("none of the profiles match")
	}
	pemBytes, err := headlessPEMEncode(ca)
	if err != nil {
		return err
	}
	if l := len(profiles); l > maxProfiles {
		log.Printf("Read %d profiles which exceeds max allowed %d. Pinging them to pick the best subset, please wait.", l, maxProfiles)
		begin := time.Now()
		pingAndSort(profiles)
		log.Printf("Pinged and sorted in %v", time.Since(begin).Round(time.Second))
		profiles = profiles[:maxProfiles]
	}
	if args.PrintOnly {
		for _, p := range profiles {
			fmt.Printf("%s\t%s\n", p.Name, p.Addr)
		}
		return nil
	}
	tArgs := struct {
		Password    string
		Username    string
		Issuer      string
		Certificate []byte
		Profiles    []profile
	}{
		Username:    args.Username,
		Password:    args.Password,
		Issuer:      certIssuer,
		Certificate: pemBytes,
		Profiles:    profiles,
	}
	if args.Out == "" {
		return tpl.Execute(os.Stdout, tArgs)
	}
	out, err := os.Create(args.Out)
	if err != nil {
		return err
	}
	defer out.Close()
	if err := tpl.Execute(out, tArgs); err != nil {
		return err
	}
	return out.Close()
}

func nameFromFile(s string) string {
	const suffix = ".ovpn"
	if !strings.HasSuffix(s, suffix) {
		return s
	}
	s = strings.TrimSuffix(s, suffix)
	if ext := path.Ext(s); strings.HasPrefix(ext, ".udp") {
		return strings.TrimSuffix(s, ext)
	}
	return s
}

func remoteAddress(openFunc func() (io.ReadCloser, error)) (string, error) {
	r, err := openFunc()
	if err != nil {
		return "", err
	}
	defer r.Close()
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if !bytes.HasPrefix(scanner.Bytes(), []byte("remote ")) {
			continue
		}
		f := strings.Fields(scanner.Text())
		if l := len(f); l != 3 {
			return "", fmt.Errorf("invalid remote specification, want 3 fields, got %d (%q)", l, scanner.Text())
		}
		return f[1], nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("cannot find remote specification")
}

func readCertificate(openFunc func() (io.ReadCloser, error)) (*pem.Block, error) {
	r, err := openFunc()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var p *pem.Block
	for {
		if p, b = pem.Decode(b); p == nil {
			return nil, fmt.Errorf("cannot find PEM-encoded certificate")
		}
		if p.Type == "CERTIFICATE" {
			p.Headers = nil
			return p, nil
		}
	}
}

func headlessPEMEncode(p *pem.Block) ([]byte, error) {
	var buf bytes.Buffer
	if err := pem.Encode(&buf, p); err != nil {
		return nil, err
	}
	b := buf.Bytes()
	const prefix = "-----BEGIN CERTIFICATE-----\n"
	const suffix = "-----END CERTIFICATE-----\n"
	if !bytes.HasPrefix(b, []byte(prefix)) || !bytes.HasSuffix(b, []byte(suffix)) {
		return nil, fmt.Errorf("certificate PEM encoding has no required prefix or suffix")
	}
	b = bytes.TrimSuffix(b, []byte(suffix))
	b = bytes.TrimPrefix(b, []byte(prefix))
	return b, nil
}

func uuid() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// pingAndSort pings every profile address and sorts profiles in order of
// increasing packet loss/RTT
func pingAndSort(profiles []profile) {
	var group errgroup.Group
	jobs := make(chan int) // indexes to profiles
	for i := 0; i < 10; i++ {
		group.Go(func() error {
			for idx := range jobs {
				p := profiles[idx]
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				st, _ := pingAddress(ctx, p.Addr, time.Second/2, 4)
				cancel()
				p.Ping = st
				profiles[idx] = p
			}
			return nil
		})
	}
	for idx := range profiles {
		jobs <- idx
	}
	close(jobs)
	group.Wait()
	sort.Slice(profiles, func(i, j int) bool {
		ri, rj := profiles[i].Ping, profiles[j].Ping
		if ri.Sent != rj.Sent {
			return ri.Sent > rj.Sent
		}
		if ri.Lost != rj.Lost {
			return ri.Lost < rj.Lost
		}
		return ri.AvgRTT < rj.AvgRTT
	})
}

type profile struct {
	Name, Addr string
	Ondemand   bool
	Ping       ping.Summary
}

func pingAddress(ctx context.Context, addr string, delay time.Duration, count int) (ping.Summary, error) {
	p, err := ping.NewICMP(addr)
	if err != nil {
		return ping.Summary{}, err
	}
	defer p.Close()
	ticker := time.NewTicker(delay)
	defer ticker.Stop()
pingLoop:
	for i := 0; ; i++ {
		if count > 0 && i == count {
			break
		}
		switch i {
		case 0:
		default:
			select {
			case <-ctx.Done():
				break pingLoop
			case <-ticker.C:
			}
		}
		if _, _, err := p.Ping(); err != nil {
			return ping.Summary{}, err
		}
	}
	return p.Stat(), nil
}

func init() { log.SetFlags(0) }

var tpl = template.Must(template.New("").Funcs(map[string]interface{}{
	"uuid": uuid,
}).Parse(body))

const body = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>{{$issuer := .Issuer}}{{$username := .Username}}{{$password := .Password}}
	<key>PayloadContent</key>
	<array>{{range .Profiles}}
		<dict>
			<key>IKEv2</key>
			<dict>
				<key>AuthName</key>
				<string>{{$username}}</string>
				<key>AuthPassword</key>
				<string>{{$password}}</string>
				<key>AuthenticationMethod</key>
				<string>None</string>
				<key>ChildSecurityAssociationParameters</key>
				<dict>
					<key>DiffieHellmanGroup</key>
					<integer>14</integer>
					<key>EncryptionAlgorithm</key>
					<string>AES-256</string>
					<key>IntegrityAlgorithm</key>
					<string>SHA2-256</string>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
				<key>DeadPeerDetectionRate</key>
				<string>Medium</string>
				<key>DisableMOBIKE</key>
				<integer>0</integer>
				<key>DisableRedirect</key>
				<true/>
				<key>EnableCertificateRevocationCheck</key>
				<integer>0</integer>
				<key>EnablePFS</key>
				<true/>
				<key>ExtendedAuthEnabled</key>
				<true/>
				<key>IKESecurityAssociationParameters</key>
				<dict>
					<key>DiffieHellmanGroup</key>
					<integer>14</integer>
					<key>EncryptionAlgorithm</key>
					<string>AES-256</string>
					<key>IntegrityAlgorithm</key>
					<string>SHA2-256</string>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
				<key>RemoteAddress</key>
				<string>{{.Addr}}</string>
				<key>RemoteIdentifier</key>
				<string>{{.Name}}</string>
				<key>ServerCertificateIssuerCommonName</key>
				<string>{{$issuer}}</string>
				<key>UseConfigurationAttributeInternalIPSubnet</key>
				<integer>0</integer>{{if .Ondemand}}
				<key>OnDemandEnabled</key>
				<integer>1</integer>
				<key>OnDemandRules</key>
				<array>
					<dict>
					<key>Action</key>
					<string>Connect</string>
					</dict>
				</array>{{end}}
			</dict>
			<key>IPv4</key>
			<dict>
				<key>OverridePrimary</key>
				<integer>0</integer>
			</dict>
			<key>PayloadDescription</key>
			<string>Configures VPN settings</string>
			<key>PayloadDisplayName</key>
			<string>VPN</string>
			<key>PayloadIdentifier</key>{{$id := uuid}}
			<string>com.apple.vpn.managed.{{$id}}</string>
			<key>PayloadType</key>
			<string>com.apple.vpn.managed</string>
			<key>PayloadUUID</key>
			<string>{{$id}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>Proxies</key>
			<dict>
				<key>HTTPEnable</key>
				<integer>0</integer>
				<key>HTTPSEnable</key>
				<integer>0</integer>
			</dict>
			<key>UserDefinedName</key>
			<string>ProtonVPN {{.Name}}</string>
			<key>VPNType</key>
			<string>IKEv2</string>
		</dict>{{end}}
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>ProtonVPN_ike_root.der</string>
			<key>PayloadContent</key>
			<data>
			{{printf "%s" .Certificate}}
			</data>
			<key>PayloadDescription</key>
			<string>Adds a CA root certificate</string>
			<key>PayloadDisplayName</key>
			<string>{{.Issuer}}</string>
			<key>PayloadIdentifier</key>{{$id := uuid}}
			<string>com.apple.security.root.{{$id}}</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>{{$id}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>ProtonVPN</string>
	<key>PayloadIdentifier</key>
	<string>MacBook.{{uuid}}</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>{{uuid}}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`
