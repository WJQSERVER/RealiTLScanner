package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"
)

// OutputFileWriter 结构体封装输出文件写入器和格式
type OutputFileWriter struct {
	writer  *bufio.Writer
	format  string
	mu      sync.Mutex // 添加互斥锁，保证线程安全
	results []ScanResult
}

// NewOutputFileWriter 创建 OutputFileWriter 实例
func NewOutputFileWriter(writer io.Writer, format string) *OutputFileWriter {
	return &OutputFileWriter{
		writer:  bufio.NewWriter(writer),
		format:  format,
		results: make([]ScanResult, 0), // 初始化 results 切片
	}
}

// outOK 方法写入成功的扫描结果
func (ow *OutputFileWriter) outOK(result ScanResult) {
	ow.mu.Lock()
	defer ow.mu.Unlock()
	ow.results = append(ow.results, result) // 收集结果，稍后统一写入
	slog.Debug("OutputFileWriter 收集到成功结果", "ip", result.IP, "format", ow.format)
}

// outFail 方法写入失败的扫描结果
func (ow *OutputFileWriter) outFail(result ScanResult) {
	ow.mu.Lock()
	defer ow.mu.Unlock()
	ow.results = append(ow.results, result) // 收集结果，稍后统一写入
	slog.Debug("OutputFileWriter 收集到失败结果", "ip", result.IP, "format", ow.format)
}

// WriteResults 方法在扫描结束后写入所有结果
func (ow *OutputFileWriter) WriteResults() {
	slog.Info("OutputFileWriter 开始写入结果", "format", ow.format)
	sort.Sort(ByIP(ow.results)) // 排序结果

	switch ow.format {
	case "json":
		slog.Debug("OutputFileWriter - 写入 JSON 格式")
		encoder := json.NewEncoder(ow.writer)
		encoder.SetIndent("", " ")
		if err := encoder.Encode(ow.results); err != nil {
			slog.Error("JSON 编码错误", "error", err)
		}
	case "readable":
		slog.Debug("OutputFileWriter - 写入易读文本格式")
		_, _ = ow.writer.WriteString("TLS 扫描结果:\n\n")
		for _, res := range ow.results {
			_, _ = ow.writer.WriteString("------------------------------------\n")
			_, _ = ow.writer.WriteString(fmt.Sprintf("IP 地址: %s\n", res.IP))
			_, _ = ow.writer.WriteString(fmt.Sprintf("原始输入: %s\n", res.Origin))
			_, _ = ow.writer.WriteString(fmt.Sprintf("证书域名: %s\n", res.Domain))
			_, _ = ow.writer.WriteString(fmt.Sprintf("证书颁发者: %s\n", res.Issuers))
			_, _ = ow.writer.WriteString(fmt.Sprintf("地理位置代码: %s\n", res.GeoCode))
			_, _ = ow.writer.WriteString(fmt.Sprintf("是否可行: %t\n", res.Feasible))
			_, _ = ow.writer.WriteString(fmt.Sprintf("TLS 版本: %s\n", res.TLSVersion))
			_, _ = ow.writer.WriteString(fmt.Sprintf("ALPN 协议: %s\n", res.ALPN))
			_, _ = ow.writer.WriteString("------------------------------------\n")
		}
		_, _ = ow.writer.WriteString("\n扫描完成，详细结果如上。\n")
	default:
		slog.Error("不支持的输出格式", "format", ow.format)
	}

	if err := ow.writer.Flush(); err != nil {
		slog.Error("刷新输出缓冲区错误", "format", ow.format, "error", err)
	}
	slog.Info("OutputFileWriter 结果写入完成", "format", ow.format)
}

// Close 方法刷新缓冲区并关闭写入器 (如果需要)
func (ow *OutputFileWriter) Close() {
	slog.Debug("OutputFileWriter 执行 Close 操作")
	if ow.writer != nil {
		slog.Debug("OutputFileWriter - 刷新缓冲区...")
		if err := ow.writer.Flush(); err != nil {
			slog.Error("刷新输出缓冲区错误", "error", err)
		}
		// bufio.Writer 不需要显式关闭底层 writer，由 main 函数中的文件 defer close() 处理
		slog.Info("OutputFileWriter - 缓冲区刷新完成")
	}
	slog.Info("OutputFileWriter 已关闭")

}
