package main

import (
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

// Geo 结构体用于地理位置信息查找，包含 geoip2.Reader 和互斥锁。
type Geo struct {
	geoReader *geoip2.Reader
	mu        sync.Mutex
}

// NewGeo 函数创建并初始化 Geo 对象。
func NewGeo() *Geo {
	geo := &Geo{
		mu: sync.Mutex{}, // 初始化互斥锁
	}
	reader, err := geoip2.Open("Country.mmdb") // 打开 GeoIP2 数据库文件
	if err != nil {
		slog.Warn("无法打开 Country.mmdb 数据库", "error", err) // 数据库打开失败时记录警告日志
		return geo                                       // 返回未完全初始化的 Geo 对象
	}
	slog.Info("GeoIP 功能已启用") // GeoIP 功能启用时记录信息日志
	geo.geoReader = reader   // 存储 geoip2.Reader 对象
	return geo               // 返回初始化后的 Geo 对象
}

// GetGeoNetIP 函数根据 netip.Addr 获取地理位置信息 (ISO 国家代码)。
func (o *Geo) GetGeoNetIP(ip netip.Addr) string {
	if o.geoReader == nil {
		return "N/A" // 如果 geoReader 为 nil，则返回 "N/A"
	}
	o.mu.Lock()         // 加锁，保证并发安全
	defer o.mu.Unlock() // 函数退出时解锁

	netIP := net.IP(ip.AsSlice())              // 将 netip.Addr 转换为 net.IP，以便与 geoip2-golang 库兼容
	country, err := o.geoReader.Country(netIP) // 使用 geoip2.Reader 查找国家信息
	if err != nil {
		slog.Debug("GeoIP 查找错误", "error", err, "ip", ip.String()) // 查找失败时记录调试日志
		return "N/A"                                              // 查找出错时返回 "N/A"
	}
	return country.Country.IsoCode // 返回 ISO 国家代码
}

// GetGeo 函数已弃用，请使用 GetGeoNetIP。
// Deprecated: 请使用 GetGeoNetIP 函数，以支持 netip.Addr 类型。
func (o *Geo) GetGeo(ip net.IP) string {
	slog.Warn("GetGeo 函数已弃用，请使用 GetGeoNetIP 以支持 netip.Addr")
	if o.geoReader == nil {
		return "N/A"
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	country, err := o.geoReader.Country(ip)
	if err != nil {
		slog.Debug("Error reading geo", "err", err)
		return "N/A"
	}
	return country.Country.IsoCode
}
