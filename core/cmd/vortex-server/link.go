package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"stormdns-go/vortexsrv"
)

// Link format (v2, app v1.4.0+): vortex://p/<unpadded base64url of the JSON below>.
//
//	{"schema":"whitedns.profile","version":2,"profile":{
//	   "engine":"stormdns","name":"…",
//	   "server":{"domain":"t.example.com","domains":["t.example.com","t2.example.net"],
//	             "encryption_key":"…","encryption_method":5},
//	   "vortex":{"server_version":"2.0.0","hold_max_ms":600,"min_app":"1.4.0"},
//	   "resolvers":[]}}
//
// "engine" stays "stormdns" because that is the client engine the app runs; "version":2 and
// the "vortex" block mark a Vortex server. App v1.3.0 and older refuse version 2 with their
// "profile version not supported" message, so nobody imports it into an app that cannot use
// it (decision D-27: the Vortex server is for app v1.4.0 and newer).
const (
	linkPrefix    = "vortex://p/"
	linkSchema    = "whitedns.profile"
	linkVersion   = 2
	minAppVersion = "1.4.0"
)

type linkServer struct {
	Domain           string   `json:"domain"`
	Domains          []string `json:"domains"`
	EncryptionKey    string   `json:"encryption_key"`
	EncryptionMethod int      `json:"encryption_method"`
}

type linkVortex struct {
	ServerVersion string `json:"server_version"`
	HoldMaxMs     int    `json:"hold_max_ms"`
	MinApp        string `json:"min_app"`
}

type linkProfileBody struct {
	Engine    string     `json:"engine"`
	Name      string     `json:"name"`
	Server    linkServer `json:"server"`
	Vortex    linkVortex `json:"vortex"`
	Resolvers []string   `json:"resolvers"`
}

type linkRoot struct {
	Schema  string          `json:"schema"`
	Version int             `json:"version"`
	Profile linkProfileBody `json:"profile"`
}

type linkInput struct {
	Name     string
	Domains  []string
	Key      string
	Method   int
	HoldMax  int
	Version  string
	Resolver []string
}

func buildLink(in linkInput) (string, error) {
	if len(in.Domains) == 0 {
		return "", errors.New("no domain configured")
	}
	if in.Key == "" {
		return "", errors.New("no key")
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "Vortex " + in.Domains[0]
	}
	res := in.Resolver
	if res == nil {
		res = []string{}
	}
	root := linkRoot{
		Schema:  linkSchema,
		Version: linkVersion,
		Profile: linkProfileBody{
			Engine: "stormdns",
			Name:   name,
			Server: linkServer{
				Domain:           in.Domains[0],
				Domains:          in.Domains,
				EncryptionKey:    in.Key,
				EncryptionMethod: in.Method,
			},
			Vortex:    linkVortex{ServerVersion: in.Version, HoldMaxMs: in.HoldMax, MinApp: minAppVersion},
			Resolvers: res,
		},
	}
	raw, err := json.Marshal(root)
	if err != nil {
		return "", err
	}
	return linkPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// parseLink decodes a link built by buildLink (used by tests and `link --check`).
func parseLink(link string) (linkRoot, error) {
	var r linkRoot
	if !strings.HasPrefix(link, linkPrefix) {
		return r, errors.New("not a vortex://p/ link")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, linkPrefix))
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(raw, &r)
	return r, err
}

func linkFromConfig(cfgPath, name string) (string, error) {
	cfg, err := vortexsrv.LoadConfig(cfgPath)
	if err != nil {
		return "", err
	}
	st, err := vortexsrv.LoadSettings(cfgPath)
	if err != nil {
		return "", err
	}
	key, err := vortexsrv.ReadKey(cfg)
	if err != nil {
		return "", fmt.Errorf("%w (run 'vortex-server keygen' first)", err)
	}
	domains, err := normalizeDomains(cfg.Domain)
	if err != nil {
		return "", err
	}
	if name == "" {
		name = st.Name
	}
	return buildLink(linkInput{
		Name:    name,
		Domains: domains,
		Key:     key,
		Method:  cfg.DataEncryptionMethod,
		HoldMax: int(st.HoldMax().Milliseconds()),
		Version: version(),
	})
}

func cmdLink(args []string) error {
	fs := newFlags("link")
	cfgPath := fs.String("config", defaultConfig, "server config")
	name := fs.String("name", "", "profile name shown in the app (default VORTEX_NAME)")
	quiet := fs.Bool("q", false, "print only the link")
	if err := fs.Parse(args); err != nil {
		return err
	}
	link, err := linkFromConfig(absConfig(*cfgPath), *name)
	if err != nil {
		return err
	}
	if *quiet {
		fmt.Fprintln(stdout, link)
		return nil
	}
	fmt.Fprintln(stdout, "Connection link for RayZen Vortex-53 (app v"+minAppVersion+" or newer):")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, link)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Copy the whole line and paste it in the app (Profiles > Import).")
	fmt.Fprintln(stdout, "Anyone with this link can use your server: share it privately.")
	return nil
}
