package main

import (
	"flag"     // 用于解析命令行参数
	"io"       // 提供基本的输入输出功能
	"log/slog" // 日志记录
	"net/http" // HTTP 客户端
	"os"       // 操作系统功能
	"regexp"   // 正则表达式操作
	"strings"  // 字符串处理
	"sync"     // 处理并发
	"time"     // 时间处理
)

// 定义全局变量用于存储命令行参数
var addr string
var in string
var port int
var thread int
var out string
var timeout int
var verbose bool
var enableIPv6 bool
var url string

func main() {
	// 清除环境变量，确保不受代理影响
	_ = os.Unsetenv("ALL_PROXY")
	_ = os.Unsetenv("HTTP_PROXY")
	_ = os.Unsetenv("HTTPS_PROXY")
	_ = os.Unsetenv("NO_PROXY")

	// 定义命令行参数
	flag.StringVar(&addr, "addr", "", "Specify an IP, IP CIDR or domain to scan")
	flag.StringVar(&in, "in", "", "Specify a file that contains multiple "+
		"IPs, IP CIDRs or domains to scan, divided by line break")
	flag.IntVar(&port, "port", 443, "Specify a HTTPS port to check")
	flag.IntVar(&thread, "thread", 2, "Count of concurrent tasks")
	flag.StringVar(&out, "out", "out.csv", "Output file to store the result")
	flag.IntVar(&timeout, "timeout", 10, "Timeout for every check")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&enableIPv6, "46", false, "Enable IPv6 in additional to IPv4")
	flag.StringVar(&url, "url", "", "Crawl the domain list from a URL, "+
		"e.g. https://launchpad.net/ubuntu/+archivemirrors")
	flag.Parse() // 解析命令行参数

	// 设置日志级别
	if verbose {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug, // 调试模式
		})))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo, // 信息模式
		})))
	}

	// 检查输入的参数，确保只提供一个
	if !ExistOnlyOne([]string{addr, in, url}) {
		slog.Error("You must specify and only specify one of `addr`, `in`, or `url`")
		flag.PrintDefaults() // 打印命令行参数的默认值
		return
	}

	// 设置输出文件
	outWriter := io.Discard // 默认丢弃输出
	if out != "" {
		f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644) // 创建或打开输出文件
		if err != nil {
			slog.Error("Error opening file", "path", out)
			return
		}
		defer f.Close()                                                      // 确保在函数结束时关闭文件
		_, _ = f.WriteString("IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE\n") // 写入CSV头部
		outWriter = f                                                        // 设置输出写入器
	}

	// 根据输入的参数选择处理方式
	var hostChan <-chan Host
	if addr != "" {
		hostChan = IterateAddr(addr) // 处理单个地址
	} else if in != "" {
		f, err := os.Open(in) // 打开包含多个地址的文件
		if err != nil {
			slog.Error("Error reading file", "path", in)
			return
		}
		defer f.Close()
		hostChan = Iterate(f) // 迭代文件中的地址
	} else {
		slog.Info("Fetching url...") // 从URL获取域名
		resp, err := http.Get(url)
		if err != nil {
			slog.Error("Error fetching url", "err", err)
			return
		}
		defer resp.Body.Close()         // 确保在函数结束时关闭响应体
		v, err := io.ReadAll(resp.Body) // 读取响应体
		if err != nil {
			slog.Error("Error reading body", "err", err)
			return
		}
		// 输出响应状态码和内容
		slog.Info("Fetched url", "status", resp.StatusCode, "body", string(v))
		// 使用正则表达式提取域名
		arr := regexp.MustCompile("(http|https)://(.*?)[/\"<>\\s]+").FindAllStringSubmatch(string(v), -1)
		var domains []string
		for _, m := range arr {
			domains = append(domains, m[2]) // 提取域名部分
		}
		domains = RemoveDuplicateStr(domains) // 去重
		slog.Info("Parsed domains", "count", len(domains))
		hostChan = Iterate(strings.NewReader(strings.Join(domains, "\n"))) // 将域名转为输入流
	}

	outCh := OutWriter(outWriter) // 创建输出通道
	defer close(outCh)            // 确保在函数结束时关闭通道
	geo := NewGeo()               // 创建地理位置对象
	var wg sync.WaitGroup         // 创建 WaitGroup 用于等待所有协程完成
	wg.Add(thread)                // 设置等待的协程数量

	// 启动多个协程进行扫描
	for i := 0; i < thread; i++ {
		go func() {
			for ip := range hostChan {
				ScanTLS(ip, outCh, geo) // 执行 TLS 扫描
			}
			wg.Done() // 完成协程的工作
		}()
	}

	t := time.Now() // 记录开始时间
	slog.Info("Started all scanning threads", "time", t)
	wg.Wait()                                                                              // 等待所有协程完成
	slog.Info("Scanning completed", "time", time.Now(), "elapsed", time.Since(t).String()) // 输出完成信息和耗时
}
