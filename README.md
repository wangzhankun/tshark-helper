# tshark-helper

## 网络分析工具集使用说明

| 工具名称 | 参数说明 | 使用说明 |
|---------|---------|---------|
| **dns-rtt.py** | `-p <pcap文件>`: 输入抓包文件<br>`-o <输出目录>`: 报告输出路径(可选) | 分析DNS时延特征：<br>`python dns-rtt.py -p traffic.pcap`<br>生成包含四类分析图表的PDF报告，自动检测DNS重传 |
| **tcp-conversions-duration.py** | `-p <pcap文件>`: 输入抓包文件<br>`-t <时间间隔>`: 统计粒度(秒)<br>`-m [basic\|advanced]`: 分析模式 | TCP连接时长分析工具：<br>`python tcp-conversions-duration.py -p traffic.pcap -t 60 -m advanced`<br>生成交互式网页图表，支持3种可视化模式 |
| **basic_info.sh** | `<pcap文件>`: 输入抓包文件<br>`<时间间隔>`: 统计窗口(秒) | 基础流量统计：<br>`./basic_info.sh traffic.pcap 10`<br>输出包含：<br>- TCP重传/丢包率统计<br>- RTT时延分布<br>- 专家诊断信息 |
| **cut_pcap.perl** | `<输入文件>`: 原始pcap<br>`<输出文件>`: 截取后的pcap<br>`-A/-B`: 起止时间(ISO 8601格式) | pcap时间截取工具：<br>`editcap -A "2024-01-01T00:00:00Z" -B "2024-01-01T00:05:00Z" input.pcap output.pcap` |
| **tcp-handshake-error.pl** | `<pcap文件>`: 输入抓包文件 | TCP握手异常检测工具：<br>`perl tcp-handshake-error.pl traffic.pcap`<br>输出三次握手不完整的TCP流ID，支持多线程分析（默认8线程） |
| **mysql-resp.pl** | `<pcap文件>`: 输入抓包文件 | MySQL响应时间分析工具：<br>`perl mysql-resp.pl traffic.pcap`<br>检测Prepare(22)/Close(25)命令响应延迟，默认阈值1秒 |


### 通用参数说明
1. 时间格式要求ISO 8601标准：`YYYY-MM-DDThh:mm:ssZ`
2. 所有工具依赖：
   - Wireshark 3.0+ (tshark)
   - Python 3.8+ with Scapy
   - Perl环境（仅cut_pcap需要）
3. 可视化报告默认输出到当前目录的`reports/`子目录