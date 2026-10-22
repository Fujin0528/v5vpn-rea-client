package main

// events.go — `/controller/v1/public/events` 长轮询。
//
// 这个接口在官方客户端里是一条**独立于资源拉取**的通道：agent 用
// `SDPClientType aTrustTray` 的 UA 发 GET，带 `fromId` 与 `timeout`，
// 服务端挂起到超时或有事件时返回。
//
// ★ 它不参与登录，也不影响资源树解析——mock 长时间返回"未实现"时，
// 登录与资源列表都正常。它影响的是**增量更新**：网关侧资源变了，
// 客户端靠这条通道收到 `EvRclistUpdated` 才会去重拉 clientResource。
//
// 事件格式来自 aTrustCore.dll 内嵌的 schema（见
// .backup/atrust/external/aTrustCore_schemas.md §1）：
//
//	{"id":n, "event":"EvRclistUpdated", "origin":"", "timestamp":unix,
//	 "sdpcguid":"<空串>", "data":{}}
//
// 六个字段全部 required。`event` 是枚举，拼错会让客户端整份文档校验失败
// 并打出 `Invalid document: #/data`——这正是 mock 未实现版本里看到的那条
// 报错，它与资源列表无关，但会污染日志、干扰排查。

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"
)

// eventEnvelope 是事件总线的一条事件。
//
// 字段顺序与 schema 的 required 列表一致，便于与文档对照。
type eventEnvelope struct {
	ID        int64          `json:"id"`
	Event     string         `json:"event"`
	Origin    string         `json:"origin"`
	Timestamp int64          `json:"timestamp"`
	SdpcGuid  string         `json:"sdpcguid"`
	Data      map[string]any `json:"data"`
}

// handleEvents 实现 events 长轮询。
//
// 语义：
//   - `timeout` 是客户端愿意等待的毫秒数（官方客户端用 110000，约 110s）
//   - `fromId` 是客户端已收到的最后一条事件 id，服务端返回 id > fromId 的事件
//   - 没有新事件时**挂起**到超时，然后返回空列表——这是长轮询的正常形态，
//     不是错误。立刻返回空列表会让客户端进入紧密重连循环，日志被刷屏。
//
// mock 默认不下发任何事件：资源是静态的，没有"变了"这回事。
// 需要验证客户端的事件处理时用 `-event` 开关手工触发一次 EvRclistUpdated。
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))

	fromID := int64(0)
	if v := r.URL.Query().Get("fromId"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			fromID = n
		}
	}

	timeoutMs := int64(60000)
	if v := r.URL.Query().Get("timeout"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			timeoutMs = n
		}
	}
	// 上限 3 分钟：再长的话 mock 关闭时会有一批 goroutine 卡在这里。
	if timeoutMs > 180000 {
		timeoutMs = 180000
	}
	wait := time.Duration(timeoutMs) * time.Millisecond

	s.mu.Lock()
	pending := s.pendingEvents(fromID)
	s.mu.Unlock()

	if len(pending) == 0 {
		// 长轮询：挂起到超时。期间若手动注入事件（-event 触发），
		// 用 channel 唤醒，避免必须等满 timeout 才把事件送出去。
		select {
		case <-time.After(wait):
		case <-s.eventWake:
		case <-r.Context().Done():
			// 客户端主动断开：直接返回，不必再写响应。
			return
		}
		s.mu.Lock()
		pending = s.pendingEvents(fromID)
		s.mu.Unlock()
	}

	s.logf("events: fromId=%d timeout=%dms → 返回 %d 条事件（body %d B）",
		fromID, timeoutMs, len(pending), len(body))

	s.replyJSON(w, map[string]any{
		"code":    0,
		"message": "成功",
		// ★ 即使没有事件也必须返回**空数组**而不是 null：
		// 客户端的 schema 要求 data 是数组（类型为 array），
		// null 会触发 `Invalid document: #/data`。
		"data": pending,
	})
}

// pendingEvents 返回 id > fromID 的事件。
//
// 这是一个**纯静态**实现：mock 不维护事件历史，只在 `-event` 开关下
// 让下一条轮询返回一条 EvRclistUpdated。这样既能验证客户端的事件分支，
// 又不会凭空制造一个真实网关不会出现的事件流。
func (s *Server) pendingEvents(fromID int64) []eventEnvelope {
	if s.nextEvent == nil || s.nextEvent.ID <= fromID {
		return nil
	}
	ev := *s.nextEvent
	s.nextEvent = nil // 只发一次
	return []eventEnvelope{ev}
}

// pushEvent 注入一条待下发事件并唤醒正在等待的轮询。
//
// 调用方不持有 s.mu。
func (s *Server) pushEvent(name string) {
	s.mu.Lock()
	s.eventSeq++
	s.nextEvent = &eventEnvelope{
		ID:        s.eventSeq,
		Event:     name,
		Origin:    "",
		Timestamp: time.Now().Unix(),
		SdpcGuid:  "",
		Data:      map[string]any{},
	}
	s.mu.Unlock()

	select {
	case s.eventWake <- struct{}{}:
	default: // 已有待处理唤醒，不必重复
	}
}

// eventJSON 用于日志里打印事件内容。
func eventJSON(ev eventEnvelope) string {
	b, err := json.Marshal(ev)
	if err != nil {
		return "<marshal error>"
	}
	return string(b)
}
