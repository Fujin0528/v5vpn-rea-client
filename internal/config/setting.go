package config

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hygkui/v5vpn-rea-client/internal/crypto"
)

// Configuration filenames for local directory
const (
	SettingXMLFilename = "setting.xml"
)

// Raw XML structures matching V5VPN setting.xml
type SettingInfoXML struct {
	XMLName xml.Name    `xml:"SETTING_INFO"`
	Common  CommonXML   `xml:"COMMON"`
	Gateway GatewayList `xml:"GATEWAY"`
}

type CommonXML struct {
	OffRelogin int `xml:"offRelogin,attr"`
	HideToTray int `xml:"HideToTray,attr"`
	LoginDebug int `xml:"LoginDebug,attr"`
	Language   int `xml:"language,attr"`
	Remember   int `xml:"remember,attr"`
	AutoLogin  int `xml:"autologin,attr"`
	TrayNotify int `xml:"trayNotify,attr"`
}

type GatewayList struct {
	LastUseGateway string       `xml:"LastUseGateway,attr"`
	Gateways       []GatewayXML `xml:",any"`
}

type GatewayXML struct {
	XMLName xml.Name `xml:""`
	Name    string   `xml:"Name,attr"`
	IP      string   `xml:"Ip,attr"`
	Port    int      `xml:"Port,attr"`
	Algo    int      `xml:"algo,attr"` // 0: Standard, 1: GM/国密
	User    UserList `xml:"USER"`
}

type UserList struct {
	LastUserName  string    `xml:"LastUserName,attr"`
	AuthType      int       `xml:"authtype,attr"`
	CertType      int       `xml:"certtype,attr"`
	CertAutoLogin int       `xml:"certautologin,attr"`
	Users         []UserXML `xml:",any"`
}

type UserXML struct {
	XMLName xml.Name `xml:""`
	Name    string   `xml:"Name,attr"` // base64
	Pwd     string   `xml:"Pwd,attr"`  // DES-CBC base64
	RPwd    int      `xml:"rpwd,attr"`
	Auto    int      `xml:"auto,attr"`
}

// UserAccount represents a decrypted user profile
type UserAccount struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
	Auto     bool   `json:"auto"`
}

// GatewayProfile represents a VPN Gateway configuration
type GatewayProfile struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	IP            string        `json:"ip"`
	Port          int           `json:"port"`
	Algo          int           `json:"algo"` // 0: Standard, 1: 国密
	LastUserName  string        `json:"lastUserName"`
	SavedAccounts []UserAccount `json:"savedAccounts"`
}

// AppConfig represents application settings used by the client
type AppConfig struct {
	SourcePath     string           `json:"sourcePath"`
	LastUseGateway string           `json:"lastUseGateway"`
	AutoLogin      bool             `json:"autoLogin"`
	Remember       bool             `json:"remember"`
	HideToTray     bool             `json:"hideToTray"`
	Gateways       []GatewayProfile `json:"gateways"`
}

// configCandidates returns the paths searched, in order, for a config file.
// The working directory and the exe directory keep compatibility with
// deployments that ship setting.xml next to the binary; configs/ is the
// source-tree layout.
func configCandidates() []string {
	candidates := []string{SettingXMLFilename}
	if exePath, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exePath), SettingXMLFilename))
	}
	return append(candidates, filepath.Join("configs", SettingXMLFilename))
}

// LoadSettingXML reads and decrypts setting.xml from the current directory,
// the executable directory, or configs/.
func LoadSettingXML(path string) (*AppConfig, error) {
	if path == "" {
		for _, candidate := range configCandidates() {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
	}
	if path == "" {
		path = SettingXMLFilename
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open %s: %w", path, err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("unable to read %s: %w", path, err)
	}

	// Standardize encoding to UTF-8
	data = EnsureUTF8(data)

	var raw SettingInfoXML
	if err := xml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse XML in %s: %w", path, err)
	}

	cfg := &AppConfig{
		SourcePath:     path,
		LastUseGateway: raw.Gateway.LastUseGateway,
		AutoLogin:      raw.Common.AutoLogin == 1,
		Remember:       raw.Common.Remember == 1,
		HideToTray:     raw.Common.HideToTray == 1,
		Gateways:       make([]GatewayProfile, 0, len(raw.Gateway.Gateways)),
	}

	for idx, gw := range raw.Gateway.Gateways {
		id := fmt.Sprintf("gw-%d", idx)
		name := gw.Name
		if name == "" {
			name = gw.IP
		}

		profile := GatewayProfile{
			ID:            id,
			Name:          name,
			IP:            gw.IP,
			Port:          gw.Port,
			Algo:          gw.Algo,
			LastUserName:  gw.User.LastUserName,
			SavedAccounts: make([]UserAccount, 0, len(gw.User.Users)),
		}

		for _, u := range gw.User.Users {
			decUser := crypto.DecodeSettingUsername(u.Name)
			decPwd, _ := crypto.DecryptSettingPassword(u.Pwd)
			profile.SavedAccounts = append(profile.SavedAccounts, UserAccount{
				Username: decUser,
				Password: decPwd,
				Remember: u.RPwd == 1,
				Auto:     u.Auto == 1,
			})
		}

		cfg.Gateways = append(cfg.Gateways, profile)
	}

	return cfg, nil
}

// SaveSettingXML serializes AppConfig back to setting.xml
func (cfg *AppConfig) SaveSettingXML(targetPath string) error {
	if targetPath == "" {
		targetPath = cfg.SourcePath
	}
	if targetPath == "" {
		targetPath = SettingXMLFilename
	}

	raw := SettingInfoXML{
		Common: CommonXML{
			HideToTray: boolToInt(cfg.HideToTray),
			Remember:   boolToInt(cfg.Remember),
			AutoLogin:  boolToInt(cfg.AutoLogin),
		},
		Gateway: GatewayList{
			LastUseGateway: cfg.LastUseGateway,
			Gateways:       make([]GatewayXML, 0, len(cfg.Gateways)),
		},
	}

	for i, gw := range cfg.Gateways {
		gwTag := fmt.Sprintf("Gateway%d", i)
		gwXML := GatewayXML{
			XMLName: xml.Name{Local: gwTag},
			Name:    gw.Name,
			IP:      gw.IP,
			Port:    gw.Port,
			Algo:    gw.Algo,
			User: UserList{
				LastUserName: gw.LastUserName,
				Users:        make([]UserXML, 0, len(gw.SavedAccounts)),
			},
		}

		for j, acc := range gw.SavedAccounts {
			uTag := fmt.Sprintf("User%d", j)
			encUser := crypto.EncodeSettingUsername(acc.Username)
			encPwd, _ := crypto.EncryptSettingPassword(acc.Password)
			gwXML.User.Users = append(gwXML.User.Users, UserXML{
				XMLName: xml.Name{Local: uTag},
				Name:    encUser,
				Pwd:     encPwd,
				RPwd:    boolToInt(acc.Remember),
				Auto:    boolToInt(acc.Auto),
			})
		}

		raw.Gateway.Gateways = append(raw.Gateway.Gateways, gwXML)
	}

	out, err := xml.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}

	header := []byte(xml.Header)
	content := append(header, out...)
	return os.WriteFile(targetPath, content, 0644)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// FindGateway retrieves a gateway by name or ID
func (cfg *AppConfig) FindGateway(identifier string) *GatewayProfile {
	for i := range cfg.Gateways {
		if strings.EqualFold(cfg.Gateways[i].Name, identifier) || cfg.Gateways[i].ID == identifier || cfg.Gateways[i].IP == identifier {
			return &cfg.Gateways[i]
		}
	}
	return nil
}
