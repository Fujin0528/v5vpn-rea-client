package protocol

import "encoding/xml"

// VersionResponse represents /vpn/version.xml response
type VersionResponse struct {
	XMLName xml.Name `xml:"VERSION"`
	Major   string   `xml:"major,attr"`
	Minor   string   `xml:"minor,attr"`
}

// AuthResponse represents the XML response from /vpn/user/auth/password
type AuthResponse struct {
	XMLName xml.Name  `xml:"RESPONSE"`
	Result  ResultTag `xml:"RESULT"`

	// CertFactorUsed is not part of the gateway XML. AuthPasswordWithCert sets
	// it when the gateway's result code asked for the certificate factor and the
	// certificate step succeeded, so the caller can tell a real two-factor
	// session from one the gateway accepted on the password alone.
	CertFactorUsed bool `xml:"-"`
}

type ResultTag struct {
	Code    string `xml:"code,attr"`
	Msg     string `xml:"msg,attr"`
	SIDName string `xml:"sid_name,attr"`
}

// IntegrationInfo represents /vpn/user/portal/intergration.xml
type IntegrationInfo struct {
	XMLName      xml.Name     `xml:"INTERGRATION_INFO"`
	Version      VersionTag   `xml:"VERSION"`
	User         UserInfo     `xml:"USER"`
	Session      SessionInfo  `xml:"SESSION"`
	Gateway      GatewayInfo  `xml:"GATEWAY"`
	ResourceList ResourceList `xml:"RESOURCE_LIST"`
	DNSInfo      DNSInfo      `xml:"DNS_INFO"`
}

type VersionTag struct {
	Major string `xml:"major,attr"`
	Minor string `xml:"minor,attr"`
}

type UserInfo struct {
	Name         string `xml:"name,attr"`
	Group        string `xml:"group,attr"`
	Type         string `xml:"type,attr"`
	AccessType   string `xml:"access_type,attr"`
	LogoutPolicy string `xml:"logout_policy,attr"`
	SSLSM2       string `xml:"ssl_sm2,attr"`
	PSKey        string `xml:"client_jump_pskey,attr"`
	// PwdOvertime 是网关给出的口令剩余有效天数（0 表示无过期策略或已取不到）。
	PwdOvertime int `xml:"pwd_overtime,attr"`
}

type SessionInfo struct {
	SIDName        string `xml:"sid_name,attr"`
	ID             string `xml:"id,attr"`
	LoginAddr      string `xml:"login-addr,attr"`
	LoginTime      string `xml:"login-time,attr"`
	CurrentTime    string `xml:"current-time,attr"`
	DetectInterval int    `xml:"detect_interval,attr"` // Seconds, e.g. 180
}

type GatewayInfo struct {
	Version string `xml:"version,attr"`
}

type ResourceList struct {
	TCPUDPResources []TCPUDPResource `xml:"TCPUDP_RESOURCE"`
}

type TCPUDPResource struct {
	Name     string `xml:"name,attr" json:"name"`
	Protocol string `xml:"protocol,attr" json:"protocol"`
	MapID    string `xml:"mapid,attr" json:"mapId"`
	Port     string `xml:"port,attr" json:"port"` // can be "24390" or "443;24390"
	Status   string `xml:"status,attr" json:"status"`
	IsTCP    string `xml:"istcp,attr" json:"isTcp"`
	// Addr 是网关直接写在资源节点上的目标地址（真实网关常见形态，例如
	// 堡垒机 addr="10.10.20.15"），与子节点 TCPUDP_IP 二选一。
	Addr      string     `xml:"addr,attr" json:"addr"`
	IPConfigs []TCPUDPIp `xml:"TCPUDP_IP" json:"ipConfigs"`
	LocalPort int        `xml:"-" json:"localPort"` // Local forwarding port assigned by client
}

type TCPUDPIp struct {
	Addr string `xml:"addr,attr" json:"addr"` // e.g. "172.19.52.4-172.19.52.4"
}

type DNSInfo struct {
	DomainHost DomainHost `xml:"DOMAIN_HOST"`
}

type DomainHost struct {
	DNSSrv   string `xml:"dnssrv,attr"`
	DNSSrvV6 string `xml:"dnssrv_v6,attr"`
}

// VPNResource represents mapped resource for UI display and proxying
type VPNResource struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	RemoteIP   string `json:"remoteIp"`
	RemotePort string `json:"remotePort"`
	LocalProxy string `json:"localProxy"`
	Status     string `json:"status"`
	MapID      string `json:"mapId,omitempty"`
	AccessURL  string `json:"accessUrl,omitempty"`
}
