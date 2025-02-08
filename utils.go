package main

import (
	"bufio"     // 提供带缓冲的 I/O
	"errors"    // 错误处理
	"fmt"       // 格式化 I/O
	"io"        // 基本 I/O 功能
	"log/slog"  // 日志记录
	"math"      // 数学常量和函数
	"math/big"  // 大整数计算
	"net"       // 网络操作
	"net/netip" // 网络 IP 操作
	"regexp"    // 正则表达式操作
	"strings"   // 字符串处理
)

// 定义主机类型常量
const (
	_              = iota // 忽略第一个常量的值
	HostTypeIP            // 主机类型为 IP
	HostTypeCIDR          // 主机类型为 CIDR
	HostTypeDomain        // 主机类型为域名
)

// 定义 HostType 类型
type HostType int

// 定义 Host 结构体，表示一个主机的信息
type Host struct {
	IP     net.IP   // 主机的 IP 地址
	Origin string   // 原始输入（IP、CIDR 或域名）
	Type   HostType // 主机类型
}

// Iterate 函数从给定的 io.Reader 读取主机信息并返回一个通道
func Iterate(reader io.Reader) <-chan Host {
	scanner := bufio.NewScanner(reader) // 创建扫描器
	hostChan := make(chan Host)         // 创建主机通道
	go func() {
		defer close(hostChan) // 确保在函数结束时关闭通道
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text()) // 去除行首尾空白
			if line == "" {
				continue // 忽略空行
			}
			ip := net.ParseIP(line) // 尝试解析 IP
			if ip != nil && (ip.To4() != nil || enableIPv6) {
				// 如果是有效的 IP 地址
				hostChan <- Host{
					IP:     ip,
					Origin: line,
					Type:   HostTypeIP,
				}
				continue
			}
			_, _, err := net.ParseCIDR(line) // 检查是否为 CIDR
			if err == nil {
				// 处理 CIDR
				p, err := netip.ParsePrefix(line) // 解析 CIDR 前缀
				if err != nil {
					slog.Warn("Invalid cidr", "cidr", line, "err", err)
				}
				if !p.Addr().Is4() && !enableIPv6 {
					continue // 如果不是 IPv4 且未启用 IPv6，跳过
				}
				p = p.Masked()   // 获取掩码的前缀
				addr := p.Addr() // 获取地址
				for {
					if !p.Contains(addr) {
						break // 如果地址不在前缀中，退出循环
					}
					ip = net.ParseIP(addr.String()) // 解析地址
					if ip != nil {
						hostChan <- Host{
							IP:     ip,
							Origin: line,
							Type:   HostTypeCIDR,
						}
					}
					addr = addr.Next() // 获取下一个地址
				}
				continue
			}
			if ValidateDomainName(line) {
				// 如果是有效的域名
				hostChan <- Host{
					IP:     nil,
					Origin: line,
					Type:   HostTypeDomain,
				}
				continue
			}
			slog.Warn("Not a valid IP, IP CIDR or domain", "line", line) // 无效输入
		}
		if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
			slog.Error("Read file error", "err", err) // 读取错误
		}
	}()
	return hostChan // 返回主机通道
}

// ValidateDomainName 函数用于验证域名的有效性
func ValidateDomainName(domain string) bool {
	r := regexp.MustCompile(`(?m)^[A-Za-z0-9\-.]+$`) // 正则表达式匹配域名
	return r.MatchString(domain)                     // 返回是否匹配
}

// ExistOnlyOne 函数检查字符串数组中是否仅存在一个非空字符串
func ExistOnlyOne(arr []string) bool {
	exist := false
	for _, item := range arr {
		if item != "" {
			if exist {
				return false // 如果存在多个非空字符串，返回 false
			} else {
				exist = true
			}
		}
	}
	return exist // 返回是否存在一个非空字符串
}

// IterateAddr 函数处理输入的地址并返回一个主机通道
func IterateAddr(addr string) <-chan Host {
	hostChan := make(chan Host)      // 创建主机通道
	_, _, err := net.ParseCIDR(addr) // 检查是否为 CIDR
	if err == nil {
		// 如果是 CIDR
		return Iterate(strings.NewReader(addr)) // 调用 Iterate 函数
	}
	ip := net.ParseIP(addr) // 尝试解析 IP
	if ip == nil {
		ip, err = LookupIP(addr) // 如果解析失败，查找 IP
		if err != nil {
			close(hostChan) // 关闭通道
			slog.Error("Not a valid IP, IP CIDR or domain", "addr", addr)
			return hostChan // 返回通道
		}
	}
	go func() {
		slog.Info("Enable infinite mode", "init", ip.String())
		lowIP := ip  // 初始化低 IP
		highIP := ip // 初始化高 IP
		hostChan <- Host{
			IP:     ip,
			Origin: addr,
			Type:   HostTypeIP,
		}
		for i := 0; i < math.MaxInt; i++ {
			if i%2 == 0 {
				lowIP = NextIP(lowIP, false) // 获取下一个低 IP
				hostChan <- Host{
					IP:     lowIP,
					Origin: lowIP.String(),
					Type:   HostTypeIP,
				}
			} else {
				highIP = NextIP(highIP, true) // 获取下一个高 IP
				hostChan <- Host{
					IP:     highIP,
					Origin: highIP.String(),
					Type:   HostTypeIP,
				}
			}
		}
	}()
	return hostChan // 返回主机通道
}

// LookupIP 函数根据地址查找 IP
func LookupIP(addr string) (net.IP, error) {
	ips, err := net.LookupIP(addr) // 查找 IP
	if err != nil {
		return nil, fmt.Errorf("failed to lookup: %w", err)
	}
	var arr []net.IP
	for _, ip := range ips {
		if ip.To4() != nil || enableIPv6 {
			arr = append(arr, ip) // 仅添加有效的 IP
		}
	}
	if len(arr) == 0 {
		return nil, errors.New("no IP found") // 如果没有找到 IP，返回错误
	}
	return arr[0], nil // 返回找到的第一个 IP
}

// RemoveDuplicateStr 函数用于去除字符串切片中的重复项
func RemoveDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool) // 创建映射以跟踪唯一项
	var list []string
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true      // 标记为唯一
			list = append(list, item) // 添加到结果列表
		}
	}
	return list // 返回去重后的列表
}

// OutWriter 函数创建一个写入通道
func OutWriter(writer io.Writer) chan<- string {
	ch := make(chan string) // 创建通道
	go func() {
		for s := range ch {
			_, _ = io.WriteString(writer, s) // 写入字符串
		}
	}()
	return ch // 返回写入通道
}

// NextIP 函数返回下一个 IP 地址
func NextIP(ip net.IP, increment bool) net.IP {
	// 将 IP 转换为 big.Int 并增量
	ipb := big.NewInt(0).SetBytes(ip)
	if increment {
		ipb.Add(ipb, big.NewInt(1)) // 增加 1
	} else {
		ipb.Sub(ipb, big.NewInt(1)) // 减少 1
	}

	// 添加前导零
	b := ipb.Bytes()
	b = append(make([]byte, len(ip)-len(b)), b...) // 确保字节长度一致
	return b                                       // 返回新的 IP 地址
}
