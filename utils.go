package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const (
	_ = iota
	HostTypeIP
	HostTypeCIDR
	HostTypeDomain
)

type HostType int

type Host struct {
	IP     netip.Addr
	Origin string
	Type   HostType
}

// Iterate reads host information and returns a channel of Hosts.
func Iterate(reader io.Reader, enableIPv6 bool) <-chan Host {
	scanner := bufio.NewScanner(reader)
	hostChan := make(chan Host)
	go func() {
		defer close(hostChan)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			if ip, err := netip.ParseAddr(line); err == nil && (ip.Is4() || enableIPv6) {
				hostChan <- Host{IP: ip, Origin: line, Type: HostTypeIP}
				continue
			}

			if p, err := netip.ParsePrefix(line); err == nil {
				if !p.Addr().Is4() && !enableIPv6 {
					continue
				}
				ipMap := make(map[netip.Addr]bool)
				for addr := p.Addr(); p.Contains(addr); addr = addr.Next() {
					if ip, err := netip.ParseAddr(addr.String()); err == nil {
						ipMap[ip] = true
					}
				}
				var wg sync.WaitGroup
				ipChan := make(chan netip.Addr)
				go func() {
					defer close(ipChan)
					for ip := range ipMap {
						ipChan <- ip
					}
				}()
				for ip := range ipChan {
					wg.Add(1)
					go func(currentIP netip.Addr) {
						defer wg.Done()
						hostChan <- Host{IP: currentIP, Origin: line, Type: HostTypeCIDR}
					}(ip)
				}
				wg.Wait()
				continue

			}

			if ValidateDomainName(line) {
				hostChan <- Host{IP: netip.Addr{}, Origin: line, Type: HostTypeDomain}
				continue
			}

			slog.Warn("Invalid input line", "line", line, "reason", "not a valid IP, CIDR, or domain")
		}

		if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
			slog.Error("File scanner error", "error", err)
		}
	}()
	return hostChan
}

// ValidateDomainName uses regex to validate domain names.
func ValidateDomainName(domain string) bool {
	domainRegex := regexp.MustCompile(`(?m)^[A-Za-z0-9\-.]+)`)
	return domainRegex.MatchString(domain)
}

// ExistOnlyOne checks if exactly one non-empty string exists in the given slice.
func ExistOnlyOne(arr []string) bool {
	nonEmptyCount := 0
	for _, item := range arr {
		if item != "" {
			nonEmptyCount++
		}
	}
	return nonEmptyCount == 1
}

// IterateAddr handles single address input, including infinite IP mode.
func IterateAddr(addr string, enableIPv6 bool) <-chan Host {
	hostChan := make(chan Host)

	if _, _, err := net.ParseCIDR(addr); err == nil {
		return Iterate(strings.NewReader(addr), enableIPv6)
	}

	ip, err := LookupIP(addr, enableIPv6)
	if err != nil {
		close(hostChan)
		slog.Error("Invalid address input", "address", addr, "error", err)
		return hostChan
	}

	go func() {
		defer close(hostChan)
		slog.Info("Infinite mode enabled", "initial_ip", ip.String())
		lowIP := ip
		highIP := ip

		hostChan <- Host{IP: ip, Origin: addr, Type: HostTypeIP}

		for i := 0; i < math.MaxInt; i++ {
			if i%2 == 0 {
				lowIP = NextIP(lowIP, false)
			} else {
				highIP = NextIP(highIP, true)
			}
			select {
			case hostChan <- Host{IP: lowIP, Origin: lowIP.String(), Type: HostTypeIP}:
			case hostChan <- Host{IP: highIP, Origin: highIP.String(), Type: HostTypeIP}:
			default:
			}
		}
	}()
	return hostChan
}

// LookupIP resolves hostname to netip.Addr.
func LookupIP(addr string, enableIPv6 bool) (netip.Addr, error) {
	ips, err := net.LookupIP(addr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("lookup failed for address '%s': %w", addr, err)
	}

	var validIPs []netip.Addr
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			if parsedIP, err := netip.ParseAddr(ip4.String()); err == nil {
				validIPs = append(validIPs, parsedIP)
			}
		} else if enableIPv6 {
			if parsedIP, err := netip.ParseAddr(ip.String()); err == nil {
				validIPs = append(validIPs, parsedIP)
			}
		}
	}

	if len(validIPs) == 0 {
		return netip.Addr{}, fmt.Errorf("no valid IP address found for '%s' (IPv6 enabled: %t)", addr, enableIPv6)
	}
	return validIPs[0], nil
}

// RemoveDuplicateStr removes duplicate strings from a slice.
func RemoveDuplicateStr(strSlice []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, item := range strSlice {
		if _, ok := seen[item]; !ok {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// ByIP implements sort.Interface for []ScanResult based on IP address.
type ByIP []ScanResult

func (a ByIP) Len() int      { return len(a) }
func (a ByIP) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByIP) Less(i, j int) bool {
	ip1, _ := netip.ParseAddr(a[i].IP)
	ip2, _ := netip.ParseAddr(a[j].IP)
	return ip1.Less(ip2)
}

// OutWriter creates output writer channel and writes output based on format.
func OutWriter(writer io.Writer, format string) chan<- ScanResult {
	outputChan := make(chan ScanResult)
	go func() {
		slog.Info(format + " 输出写入器启动")
		bufWriter := bufio.NewWriter(writer)
		defer func() {
			slog.Debug(format + " 输出写入器 - 刷新缓冲区...")
			if err := bufWriter.Flush(); err != nil {
				slog.Error("刷新输出缓冲区错误", "format", format, "error", err)
			}
			slog.Info(format + " 输出写入器已关闭")
		}()

		var results []ScanResult
		for result := range outputChan {
			slog.Debug("OutWriter 接收到结果", "ip", result.IP, "format", format) // 添加 debug 日志
			results = append(results, result)
		}

		sort.Sort(ByIP(results)) // Sort results by IP address

		switch format {
		case "json":
			slog.Debug("OutWriter - 开始 JSON 编码")
			encoder := json.NewEncoder(bufWriter)
			encoder.SetIndent("", " ") // 设置 JSON 缩进
			if err := encoder.Encode(results); err != nil {
				slog.Error("JSON 编码错误", "error", err) // 添加 debug 日志
			} else {
				slog.Debug("OutWriter - JSON 编码完成，准备写入文件") // 添加 debug 日志
			}
			slog.Debug("OutWriter - 刷新 JSON 缓冲区...")
			if err := bufWriter.Flush(); err != nil { // 显式刷新 JSON 缓冲区
				slog.Error("刷新 JSON 输出缓冲区错误", "error", err)
			}
			slog.Debug("OutWriter - JSON 缓冲区刷新完成")

		case "readable":
			slog.Debug("OutWriter - 开始写入易读文本")
			_, _ = bufWriter.WriteString("TLS 扫描结果:\n\n") // 添加总标题
			for _, res := range results {
				_, _ = bufWriter.WriteString("------------------------------------\n")
				_, _ = bufWriter.WriteString(fmt.Sprintf("IP 地址: %s\n", res.IP))
				_, _ = bufWriter.WriteString(fmt.Sprintf("原始输入: %s\n", res.Origin))
				_, _ = bufWriter.WriteString(fmt.Sprintf("证书域名: %s\n", res.Domain))
				_, _ = bufWriter.WriteString(fmt.Sprintf("证书颁发者: %s\n", res.Issuers))
				_, _ = bufWriter.WriteString(fmt.Sprintf("地理位置代码: %s\n", res.GeoCode))
				_, _ = bufWriter.WriteString(fmt.Sprintf("是否可行: %t\n", res.Feasible))
				_, _ = bufWriter.WriteString(fmt.Sprintf("TLS 版本: %s\n", res.TLSVersion))
				_, _ = bufWriter.WriteString(fmt.Sprintf("ALPN 协议: %s\n", res.ALPN))
				_, _ = bufWriter.WriteString("------------------------------------\n")
			}
			_, _ = bufWriter.WriteString("\n扫描完成，详细结果如上。\n") // 添加结尾语
			slog.Debug("OutWriter - 易读文本写入完成，准备刷新缓冲区")
			if err := bufWriter.Flush(); err != nil { // 显式刷新易读文本缓冲区
				slog.Error("刷新易读文本输出缓冲区错误", "error", err)
			}
			slog.Debug("OutWriter - 易读文本缓冲区刷新完成")

		default:
			slog.Error("不支持的输出格式", "format", format)
		}
	}()
	return outputChan
}

// NextIP calculates next IP address (increment/decrement for netip.Addr).
func NextIP(ip netip.Addr, increment bool) netip.Addr {
	ipBytes := ip.As4()
	ipInt := uint32(ipBytes[0])<<24 | uint32(ipBytes[1])<<16 | uint32(ipBytes[2])<<8 | uint32(ipBytes[3])

	if increment {
		ipInt++
	} else {
		ipInt--
	}

	newIPBytes := make(net.IP, net.IPv4len)
	newIPBytes[0] = byte(ipInt >> 24)
	newIPBytes[1] = byte(ipInt >> 16)
	newIPBytes[2] = byte(ipInt >> 8)
	newIPBytes[3] = byte(ipInt)

	if parsedIP, err := netip.ParseAddr(newIPBytes.String()); err == nil {
		return parsedIP
	}
	return netip.Addr{}
}
