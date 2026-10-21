package service

// atrust_service.go — aTrust 后端服务。
//
// 与 VPNService 的关系（§14.5.2 边界二、边界三）：
//
//   - 不复用、不继承、不修改 VPNService 的任何方法签名。
//     aTrust 走自己的类型，由 main.go 用 mygo.BindAs("ATrustService", …)
//     单独注册（mygo 按服务名注册，同名会 panic）。
//   - 配置读写与日志通过 ATrustHost 接口借用，不直接持有
//     *config.AppConfig —— 配置由 VPNService 的锁保护，绕过它去改
//     会与 SaveGateway/Login 竞争。
//   - 连接状态是本结构体自己的字段。因此 aTrust 侧的失败（panic、超时、
//     认证错）不会把 V5VPN 的会话状态改坏，退出钩子也能按后端分别处理。
//
// ⚠ 数据面尚未实现。本服务完成的是控制面登录与会话维持；aTrust 真正的
// 流量通道是 TLS:441 + SOCKS5（§16），不在本文件范围内。资源列表目前
// 只做展示，启动它不会让内网可达——这一点在登录日志里会明确写出来，
// 免得用户以为已经能访问。

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hygkui/v5vpn-rea-client/internal/atrust"
	"github.com/hygkui/v5vpn-rea-client/internal/config"
)

// atrustLoginTimeout 限制认证链（authConfig → psw → authCheck → onlineInfo）
// 的总时长。单个请求另有 30s 上限，这里管的是整条链，
// 避免某个端点半死不活时把登录按钮永久卡住。
const atrustLoginTimeout = 30 * time.Second

// atrustResourceTimeout 限制资源树拉取。
const atrustResourceTimeout = 30 * time.Second

// ATrustHost 是 ATrustService 向宿主（VPNService）借用的能力。
//
// 把它抽成接口而不是直接依赖 *VPNService，有两个目的：
//   - 测试里不需要构造完整的 VPNService（那会去读 setting.xml）
//   - 边界二是双向的：aTrust 侧只应看到"读写配置 + 记日志"这几个动作，
//     看不到 VPNService 的连接、代理、证书等能力
type ATrustHost interface {
	GetConfig() *config.AppConfig
	SaveGateway(gw config.GatewayProfile) error
	GetLogs() []string
	Log(level string, format string, args ...any)
}

// ATrustService 是 aTrust 后端的会话与状态容器。
type ATrustService struct {
	host ATrustHost

	// Client 是当前会话的控制面客户端；未连接时为 nil。
	Client *atrust.Client

	Status       string // "Disconnected" / "Connecting" / "Connected" / "Error"
	StatusDetail string

	Resources     []atrust.Resource
	resourceState ResourceLoadState
	resourceError string

	username string

	// OnStatusChange 在状态变化时被异步调用，用于刷新托盘与窗口尺寸。
	OnStatusChange func(string)

	mu sync.Mutex
}

// NewATrustService 创建 aTrust 后端服务。
func NewATrustService(host ATrustHost) *ATrustService {
	return &ATrustService{
		host:         host,
		Status:       "Disconnected",
		StatusDetail: "Ready",
	}
}

// ---------- 状态 ----------

func (s *ATrustService) setStatus(status, detail string) {
	s.mu.Lock()
	s.Status = status
	s.StatusDetail = detail
	fn := s.OnStatusChange
	s.mu.Unlock()
	if fn != nil {
		go fn(status)
	}
}

// IsActive 报告当前是否有 aTrust 会话（连接中或已连接）。
//
// 退出钩子用它来决定要不要调本后端的 Logout —— 这是边界三的落点：
// V5VPN 未连接时不该因为 aTrust 的退出流程而被写一条 "Tearing down" 日志。
func (s *ATrustService) IsActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Status == "Connecting" || s.Status == "Connected"
}

// GetStatus 返回与 VPNService.GetStatus 同形的状态快照。
//
// 键集合必须一致：UI 的 showConnectedView / renderResources 按这些键取值，
// 少一个就是空白区域而不是报错。
func (s *ATrustService) GetStatus() map[string]any {
	s.mu.Lock()
	status := s.Status
	detail := s.StatusDetail
	resources := s.Resources
	state := string(s.resourceState)
	resErr := s.resourceError
	s.mu.Unlock()

	return map[string]any{
		"status":         status,
		"statusDetail":   detail,
		"resources":      resources,
		"resourceState":  state,
		"resourceError":  resErr,
		"resourceCount":  len(resources),
		"lastUseGateway": s.lastUseGateway(),
		"logCount":       len(s.host.GetLogs()),
		"protocol":       config.ProtocolATrust,
	}
}

func (s *ATrustService) lastUseGateway() string {
	if cfg := s.host.GetConfig(); cfg != nil {
		return cfg.LastUseGateway
	}
	return ""
}

// ---------- 登录 ----------

// Login 执行 aTrust 口令登录。
//
// 返回的 map 与 VPNService.Login 完全同形（status/username/authType/
// sessionId/resourceState/resourceCount/resources），因此 UI 的
// showConnectedView() 不需要为 aTrust 写第二套渲染。
//
// 资源列表异步加载：认证成功后立即返回，让界面先进入已连接视图。
func (s *ATrustService) Login(gwIdentifier, username, password string, remember, auto bool) (map[string]any, error) {
	cfg := s.host.GetConfig()
	if cfg == nil {
		return nil, fmt.Errorf("配置尚未加载")
	}
	gw := cfg.FindGateway(gwIdentifier)
	if gw == nil {
		return nil, fmt.Errorf("gateway %q not found", gwIdentifier)
	}

	// 后端分流必须在这一层再校验一次。UI 按 gateway.protocol 选 endpoint，
	// 一旦那边判断出错，把 V5VPN 网关交给 aTrust 后端会得到
	// "不是 aTrust 网关" 这种让人摸不着头脑的错误；显式检查能直接说清原因。
	//
	// 失败也要落成 Error 状态：留在 Disconnected 会让界面表现为
	// "点了连接没有任何反应"，比一条明确错误更难排查。
	if !gw.IsATrust() {
		err := fmt.Errorf("网关 %q 的协议是 %s，不能由 aTrust 后端登录",
			gw.Name, gw.EffectiveProtocol())
		s.setStatus("Error", err.Error())
		return nil, err
	}

	address := atrustGatewayURL(*gw)
	if address == "" {
		err := fmt.Errorf("网关 %q 缺少地址", gw.Name)
		s.setStatus("Error", err.Error())
		return nil, err
	}

	soc := *gw // 副本：SaveGateway 需要完整字段，这里只改账号部分
	if remember {
		s.saveAccount(soc, username, password, remember, auto)
	}

	// 拆掉可能残留的旧会话。aTrust 的控制面会话是服务端状态，
	// 不主动登出会让网关侧留下一个孤儿在线记录。
	s.mu.Lock()
	stale := s.Client
	s.Client = nil
	s.Resources = nil
	s.resourceState = ""
	s.resourceError = ""
	s.Status = "Connecting"
	s.StatusDetail = fmt.Sprintf("正在连接 %s (%s)...", gw.Name, address)
	fn := s.OnStatusChange
	s.mu.Unlock()
	if stale != nil {
		stale.Close()
	}
	if fn != nil {
		go fn("Connecting")
	}

	s.host.Log("INFO", "aTrust: 正在登录 %s (%s)，用户 %s", gw.Name, address, username)

	logf := func(format string, args ...any) {
		s.host.Log("INFO", "aTrust: "+format, args...)
	}
	client, err := atrust.NewClient(address, atrust.Options{
		// aTrust 网关普遍使用企业自签证书，与 V5VPN 侧的处理一致
		// （protocol.GatewayTLSConfig 也是 InsecureSkipVerify）。
		InsecureSkipVerify: true,
		Logf:               logf,
	})
	if err != nil {
		s.setStatus("Error", fmt.Sprintf("网关地址无效: %v", err))
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), atrustLoginTimeout)
	defer cancel()

	if _, err := client.Authenticate(ctx, username, password); err != nil {
		client.Close()
		msg := atrustLoginError(err)
		s.setStatus("Error", msg)
		return nil, err
	}

	return s.enterConnected(client, username), nil
}

// enterConnected 发布已连接状态并异步拉取应用列表。
func (s *ATrustService) enterConnected(client *atrust.Client, username string) map[string]any {
	s.mu.Lock()
	s.Client = client
	s.username = username
	s.Resources = nil
	s.resourceState = ResourceLoading
	s.resourceError = ""
	s.Status = "Connected"
	s.StatusDetail = "已连接，正在拉取 aTrust 应用列表..."
	fn := s.OnStatusChange
	s.mu.Unlock()
	if fn != nil {
		go fn("Connected")
	}

	s.host.Log("SUCCESS", "aTrust: 认证成功，会话已建立；正在后台拉取应用列表...")
	// 数据面没实现这件事必须说出来。静默地展示一个资源列表，
	// 会让人以为点击即可访问内网。
	s.host.Log("INFO", "aTrust: 当前版本仅完成控制面（登录/会话/资源列表）；"+
		"数据面通道 TLS:441 + SOCKS5 尚未实现，应用列表暂不可访问")

	go s.loadResources(client)

	return map[string]any{
		"status":        "Connected",
		"username":      username,
		"authType":      "password",
		"sessionId":     client.SidTicket(),
		"resourceState": string(ResourceLoading),
		"resourceCount": 0,
		"resources":     []atrust.Resource{},
	}
}

// loadResources 拉取 clientResource 并投影成 UI 形状。
//
// 失败不改变已连接状态：会话本身是有效的，用户可以在资源表上点重试
// （RefreshResources），与 V5VPN 侧「已连接、资源为空」的语义一致。
func (s *ATrustService) loadResources(client *atrust.Client) {
	s.host.Log("INFO", "aTrust: 正在获取应用列表...")

	ctx, cancel := context.WithTimeout(context.Background(), atrustResourceTimeout)
	defer cancel()

	raw, err := client.ClientResource(ctx)

	s.mu.Lock()
	if s.Client != client {
		// 拉取期间会话被替换或登出了。
		s.mu.Unlock()
		return
	}
	if err != nil {
		s.Resources = nil
		s.resourceState = ResourceError
		s.resourceError = err.Error()
		s.StatusDetail = "已连接，但获取 aTrust 应用列表失败"
		fn := s.OnStatusChange
		s.mu.Unlock()
		if fn != nil {
			go fn("Connected")
		}
		s.host.Log("WARN", "aTrust: 获取应用列表失败（会话仍有效，可重试）: %v", err)
		return
	}

	items, unknownKeys := atrust.ExtractResources(raw)
	s.Resources = items
	s.resourceState = ResourceReady
	s.resourceError = ""
	s.StatusDetail = fmt.Sprintf("已连接 %s（%d 个应用）", s.username, len(items))
	fn := s.OnStatusChange
	s.mu.Unlock()

	if fn != nil {
		go fn("Connected")
	}

	// unknownKeys 是 resource.go 的排查钩子：如果真实网关用了我们没预料
	// 的顶层键，这里会把候选列出来，而不是让资源表静默地空着。
	if len(items) == 0 && len(unknownKeys) > 0 {
		s.host.Log("WARN", "aTrust: 资源树里没有识别出应用数组，顶层键为 %v；"+
			"若确为资源数据，请把它们加入 resourceArrayKeys", unknownKeys)
	}
	s.host.Log("SUCCESS", "aTrust: 已加载 %d 个应用。", len(items))
}

// RefreshResources 重新拉取应用列表，供 UI 的「重试」按钮使用。
func (s *ATrustService) RefreshResources() (map[string]any, error) {
	s.mu.Lock()
	client := s.Client
	if client == nil || s.Status != "Connected" {
		s.mu.Unlock()
		return nil, fmt.Errorf("当前没有已连接的 aTrust 会话")
	}
	s.resourceState = ResourceLoading
	s.resourceError = ""
	s.StatusDetail = "正在重新获取 aTrust 应用列表..."
	s.mu.Unlock()

	s.host.Log("INFO", "aTrust: 正在刷新应用列表...")

	ctx, cancel := context.WithTimeout(context.Background(), atrustResourceTimeout)
	defer cancel()

	raw, err := client.ClientResource(ctx)
	if err != nil {
		s.mu.Lock()
		s.resourceState = ResourceError
		s.resourceError = err.Error()
		s.StatusDetail = "已连接，但获取 aTrust 应用列表失败"
		s.mu.Unlock()
		return nil, err
	}

	items, unknownKeys := atrust.ExtractResources(raw)

	s.mu.Lock()
	if s.Client != client {
		s.mu.Unlock()
		return nil, fmt.Errorf("会话已在刷新期间结束")
	}
	s.Resources = items
	s.resourceState = ResourceReady
	s.resourceError = ""
	s.StatusDetail = fmt.Sprintf("已连接 %s（%d 个应用）", s.username, len(items))
	s.mu.Unlock()

	if len(items) == 0 && len(unknownKeys) > 0 {
		s.host.Log("WARN", "aTrust: 资源树里没有识别出应用数组，顶层键为 %v", unknownKeys)
	}
	s.host.Log("SUCCESS", "aTrust: 已刷新 %d 个应用。", len(items))

	return map[string]any{
		"status":        "Connected",
		"resourceState": string(ResourceReady),
		"resourceCount": len(items),
		"resources":     items,
	}, nil
}

// ---------- 登出 ----------

// Logout 结束 aTrust 会话并清空本地状态。
//
// 返回 (bool, error) 与 VPNService.Logout 同形：mygo 的 IPC 桥按
// (value, error) 编码，前端两边可以用同一段代码调用。
func (s *ATrustService) Logout() (bool, error) {
	s.mu.Lock()
	client := s.Client
	s.Client = nil
	s.Resources = nil
	s.resourceState = ""
	s.resourceError = ""
	s.username = ""
	s.Status = "Disconnected"
	s.StatusDetail = "Disconnected"
	fn := s.OnStatusChange
	s.mu.Unlock()

	if fn != nil {
		go fn("Disconnected")
	}

	if client == nil {
		return true, nil
	}

	s.host.Log("INFO", "aTrust: 正在断开连接...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := client.LogoutAndClear(ctx)
	client.Close()

	if err != nil {
		// 本地状态已经清空，远端登出失败只是网关侧可能留一条在线记录，
		// 不应让 UI 停在"已连接"。
		s.host.Log("WARN", "aTrust: 网关登出请求失败（本地会话已清除）: %v", err)
		return true, nil
	}
	s.host.Log("SUCCESS", "aTrust: 已断开连接。")
	return true, nil
}

// ---------- 内部 ----------

// saveAccount 把本次使用的账号写回网关配置。
//
// 走 host.SaveGateway 而不是直接改配置：配置由 VPNService 的锁保护，
// 并且 SaveGateway 负责把改动落盘到 setting.xml。
func (s *ATrustService) saveAccount(gw config.GatewayProfile, username, password string, remember, auto bool) {
	gw.LastUserName = username
	for i := range gw.SavedAccounts {
		if gw.SavedAccounts[i].Username == username {
			gw.SavedAccounts[i].Password = password
			gw.SavedAccounts[i].Remember = remember
			gw.SavedAccounts[i].Auto = auto
			if err := s.host.SaveGateway(gw); err != nil {
				s.host.Log("WARN", "aTrust: 保存账号失败: %v", err)
			}
			return
		}
	}
	gw.SavedAccounts = append(gw.SavedAccounts, config.UserAccount{
		Username: username,
		Password: password,
		Remember: remember,
		Auto:     auto,
	})
	if err := s.host.SaveGateway(gw); err != nil {
		s.host.Log("WARN", "aTrust: 保存账号失败: %v", err)
	}
}

// atrustGatewayURL 把网关配置拼成 atrust.NewClient 认识的地址。
//
// 用户的输入形态并不统一：可能只填主机名，也可能把完整 URL 粘进来。
// 两种都要能吃下，且不能拼出 https://host:8443:443 这种畸形地址。
func atrustGatewayURL(gw config.GatewayProfile) string {
	host := strings.TrimSpace(gw.IP)
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		// 用户填了完整地址：以地址里的端口为准，不再追加。
		return host
	}
	// 已经自带端口（host:8443）或 IPv6 字面量（2001:db8::1）时不追加。
	if strings.Contains(host, ":") && !strings.Contains(host, "::") {
		return "https://" + host
	}
	port := gw.Port
	if port <= 0 {
		port = 443
	}
	return fmt.Sprintf("https://%s:%d", host, port)
}

// atrustLoginError 把协议层错误翻译成用户能读的一句话。
//
// 原始错误会原样返回给调用方（API 层据此设状态码），这里只产出展示文案。
func atrustLoginError(err error) string {
	switch {
	case atrust.IsMultiFactorRequired(err):
		return "网关要求多因子认证，当前版本仅支持口令单步登录"
	case atrust.IsNotATrustGateway(err):
		return "目标地址不是 aTrust 网关"
	case errors.Is(err, atrust.ErrNoSession):
		return "认证未建立会话（网关未返回 sidTicket）"
	}
	if code, ok := atrust.IsAPIError(err); ok {
		return fmt.Sprintf("aTrust 网关拒绝登录（错误码 %d）: %v", code, err)
	}
	return fmt.Sprintf("aTrust 登录失败: %v", err)
}

// ATrustErrorCode 把 aTrust 的失败翻译成 UI 认识的稳定错误码。
//
// 与 AuthErrorCode（V5VPN 侧）是并列关系而不是替代关系：
// 前端按 code 分支显示提示，两套码值不应混用。
func ATrustErrorCode(err error) string {
	switch {
	case atrust.IsMultiFactorRequired(err):
		return "mfa_required"
	case atrust.IsNotATrustGateway(err):
		return "not_atrust_gateway"
	}
	return ""
}
