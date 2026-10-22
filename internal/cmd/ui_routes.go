package main

// ui_routes.go —— 启动时先打开哪一套界面。
//
// 两套前端按协议物理分家，分别挂在 /v5vpn/ 与 /atrust/ 下（uiFS 是
// 剥掉 "ui/" 前缀的子文件系统，FileServer 直接以这些子目录对外）。
// 窗口入口只有一个根路径，所以需要一条明确的规则挑界面。规则：看
// setting.xml 里 lastUseGateway 指向的网关的协议 —— 上次用哪类网关，
// 这次启动就落在哪套界面上。
//
// 没有记录、或记录对应的网关已被删除时按 V5VPN 处理：GatewayProfile
// 的 protocol 零值就是 V5VPN，老配置文件里根本没有这个字段；这与后端
// "零值 = V5VPN" 的语义一致。反过来 aTrust 必须显式声明，绝不能默认
// 归属 —— 猜错会把用户送进一套连不上的界面。

import "github.com/hygkui/v5vpn-rea-client/internal/config"

const (
	uiPathV5VPN  = "/v5vpn/"
	uiPathATrust = "/atrust/"
)

// initialUIPath 返回启动时（以及根路径重定向时）应当打开的界面目录。
func initialUIPath(cfg *config.AppConfig) string {
	if cfg == nil || cfg.LastUseGateway == "" {
		return uiPathV5VPN
	}
	if gw := cfg.FindGateway(cfg.LastUseGateway); gw != nil && gw.IsATrust() {
		return uiPathATrust
	}
	return uiPathV5VPN
}
