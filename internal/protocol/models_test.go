package protocol

import (
	"encoding/xml"
	"testing"
)

// TestTCPUDPResourceParsesAddrAttr 覆盖真实网关的网页类资源形态：
// 目标地址写在资源节点的 addr 属性上、port 为区间、无 TCPUDP_IP 子节点。
func TestTCPUDPResourceParsesAddrAttr(t *testing.T) {
	src := `<TCPUDP name="堡垒机" protocol="TCP" mapid="M_100" port="1-65535"
		status="1" istcp="1" addr="10.10.20.15"></TCPUDP>`
	var r TCPUDPResource
	if err := xml.Unmarshal([]byte(src), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.Addr != "10.10.20.15" {
		t.Fatalf("Addr = %q, want 10.10.20.15", r.Addr)
	}
	if r.Port != "1-65535" {
		t.Fatalf("Port = %q, want 1-65535", r.Port)
	}
	if r.MapID != "M_100" {
		t.Fatalf("MapID = %q, want M_100", r.MapID)
	}
	if len(r.IPConfigs) != 0 {
		t.Fatalf("IPConfigs = %v, want none", r.IPConfigs)
	}
}

// TestTCPUDPResourceStillParsesIPSubnode 确认子节点形态不受影响
// （单端口资源仍走 TCPUDP_IP）。
func TestTCPUDPResourceStillParsesIPSubnode(t *testing.T) {
	src := `<TCPUDP name="单端口" mapid="M_200" port="443">
		<TCPUDP_IP addr="192.168.1.10" port="443"/>
	</TCPUDP>`
	var r TCPUDPResource
	if err := xml.Unmarshal([]byte(src), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(r.IPConfigs) != 1 || r.IPConfigs[0].Addr != "192.168.1.10" {
		t.Fatalf("IPConfigs = %+v, want 192.168.1.10", r.IPConfigs)
	}
	if r.Addr != "" {
		t.Fatalf("Addr = %q, want empty", r.Addr)
	}
}

// TestUserInfoParsesPwdOvertime 覆盖口令剩余有效天数字段的解析。
func TestUserInfoParsesPwdOvertime(t *testing.T) {
	src := `<USER name="alice" pwd_overtime="7"/>`
	var u UserInfo
	if err := xml.Unmarshal([]byte(src), &u); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if u.PwdOvertime != 7 {
		t.Fatalf("PwdOvertime = %d, want 7", u.PwdOvertime)
	}
}
