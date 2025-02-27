#!/usr/bin/env python3

#%%

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import argparse
import sys
import os
import matplotlib.pyplot as plt
import numpy as np
import matplotlib as mpl

# 设置中文字体和符号显示
mpl.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'WenQuanYi Zen Hei']  # 设置中文字体
mpl.rcParams['axes.unicode_minus'] = False  # 正确显示负号

#%%
def calculate_dns_rtt(pcap_file):
    # 存储事务信息 { id: { first_query: time, last_response: time } }
    transactions = {}
    rtt_list = []
    
    def process_packet(pkt):
        if pkt.haslayer(DNS) and pkt.haslayer(IP):
            dns = pkt.getlayer(DNS)
            ip = pkt.getlayer(IP)
            transport = pkt.getlayer(UDP) or pkt.getlayer(TCP)
            
            if not transport:
                return
            
            # 构建事务唯一标识：考虑方向、IP和端口
            if pkt[IP].src == ip.src:  # 判断数据包方向
                src_ip = ip.src
                src_port = transport.sport
                dst_ip = ip.dst
                dst_port = transport.dport
            else:
                src_ip = ip.dst
                src_port = transport.dport
                dst_ip = ip.src
                dst_port = transport.sport
            
            # 唯一标识 = ID + 源IP+端口 + 目的IP+端口
            transaction_key = (dns.id, src_ip, src_port, dst_ip, dst_port)

            if dns.qr == 0:  # 查询包
                current_time = pkt.time
                if transaction_key not in transactions:
                    transactions[transaction_key] = {
                        'query_time': current_time,
                        'response_time': None,
                        'retransmit': 0
                    }
                else:
                    # 记录重传
                    transactions[transaction_key]['retransmit'] += 1
                
            elif dns.qr == 1:  # 响应包
                # 查找匹配的请求（交换源目的）
                reverse_key = (dns.id, dst_ip, dst_port, src_ip, src_port)
                if reverse_key in transactions:
                    transactions[reverse_key]['response_time'] = pkt.time

    # 读取并处理pcap文件
    try:
        sniff(offline=pcap_file, prn=process_packet, store=0)
    except Exception as e:
        print(f"错误: 无法读取pcap文件 - {str(e)}")
        return

    # 计算RTT时记录事务ID
    transaction_rtts = []
    for key, data in transactions.items():
        if data['response_time'] is not None:
            rtt = (data['response_time'] - data['query_time']) * 1000
            # 记录重传次数
            rtt_list.append( (rtt, data['retransmit']) )
            transaction_rtts.append(key)

    # 输出统计结果
    if not rtt_list:
        print("未找到匹配的DNS请求/响应")
        return

    # 新增最大1%事务ID输出
    print(f"\n按照 dns 事务统计RTT:")
    print(f"分析完成，共匹配 {len(rtt_list)} 个DNS事务")
    print(f"事务平均RTT: {sum(rtt for rtt, _ in rtt_list)/len(rtt_list):.2f} ms")
    print(f"事务最小RTT: {min(rtt for rtt, _ in rtt_list):.2f} ms")
    print(f"事务最大RTT: {max(rtt for rtt, _ in rtt_list):.2f} ms")
    print(f"中位数RTT: {np.median([rtt for rtt, _ in rtt_list]):.2f} ms")
    print(f"95百分位RTT: {np.percentile([rtt for rtt, _ in rtt_list], 95):.2f} ms")
    print(f"99百分位RTT: {np.percentile([rtt for rtt, _ in rtt_list], 99):.2f} ms")
    
    # 计算前1%的事务ID
    if transaction_rtts:
        # 按RTT降序排序
        sorted_transactions = sorted(transaction_rtts, key=lambda x: transactions[x]['response_time'] - transactions[x]['query_time'], reverse=True)
        # 计算1%的数量（至少1个）
        top_count = max(1, int(len(sorted_transactions) * 0.01))
        top_transactions = sorted_transactions[:top_count]
        
        print(f"\nTop 1% 高延迟事务（共{top_count}个）:")
        for tid in top_transactions:
            print(f"事务ID: {tid}, RTT: {(transactions[tid]['response_time'] - transactions[tid]['query_time']) * 1000:.2f} ms")

        # 确保数据有效性
        rtt_array = np.array([rtt for rtt, _ in rtt_list], dtype=np.float64)
        if rtt_array.size == 0:
            print("无有效RTT数据可绘制")
            return
        
        # 修改绘图部分代码
        plt.figure(figsize=(15, 10))
        
        # 使用科学分箱方法（Freedman-Diaconis rule）
        iqr = np.subtract(*np.percentile(rtt_array, [75, 25]))
        bin_width = 2 * iqr * (len(rtt_array) ** (-1/3))
        bin_count = int(np.ceil((max(rtt_array) - min(rtt_array)) / bin_width)) if bin_width > 0 else 10
        bin_count = min(bin_count, 20)  # 限制最大分箱数
        
        # 创建多图布局
        plt.subplot(2, 2, 1)
        # 概率密度直方图
        n, bins, patches = plt.hist(rtt_array, bins=bin_count, density=True, 
                                   alpha=0.7, color='steelblue', edgecolor='white')
        plt.title('RTT Distribution Histogram')
        plt.xlabel('RTT (ms)')
        plt.ylabel('Probability Density')
        plt.grid(True, linestyle='--', alpha=0.6)
        
        # 累积分布图
        plt.subplot(2, 2, 2)
        valid_rtt = rtt_array[np.isfinite(rtt_array)]
        counts, bin_edges = np.histogram(valid_rtt, bins=50, density=True)
        cdf = np.cumsum(counts) * np.diff(bin_edges)
        plt.plot(bin_edges[1:], cdf, 'r-', linewidth=2)
        plt.title('Cumulative Distribution')
        plt.xlabel('RTT (ms)')
        plt.ylabel('Probability')
        plt.grid(True, linestyle='--', alpha=0.6)
        
        # 箱线图
        plt.subplot(2, 2, 3)
        plt.boxplot(rtt_array, vert=False, patch_artist=True,
                   boxprops=dict(facecolor='lightblue'),
                   medianprops=dict(color='red'))
        plt.title('Boxplot Distribution')
        plt.xlabel('RTT (ms)')
        plt.grid(True, linestyle='--', alpha=0.6)
        
        # 新增异常值标注
        q1 = np.percentile(rtt_array, 25)
        q3 = np.percentile(rtt_array, 75)
        iqr = q3 - q1
        upper_bound = q3 + 1.5 * iqr
        lower_bound = q1 - 1.5 * iqr
        outliers = [x for x in rtt_array if x > upper_bound or x < lower_bound]
        plt.text(0.7, 0.9, f'异常值数量: {len(outliers)}', 
                 transform=plt.gca().transAxes, 
                 bbox=dict(facecolor='white', alpha=0.8))
        
        # KDE密度图
        plt.subplot(2, 2, 4)
        from scipy.stats import gaussian_kde
        kde = gaussian_kde(valid_rtt)
        x = np.linspace(valid_rtt.min(), valid_rtt.max(), 1000)
        plt.plot(x, kde(x), 'g-', linewidth=2)
        plt.fill_between(x, kde(x), alpha=0.2, color='green')
        plt.title('Probability Density Estimate')
        plt.xlabel('RTT (ms)')
        plt.ylabel('Density')
        plt.grid(True, linestyle='--', alpha=0.6)
        
        plt.tight_layout()
        output_path = args.output if 'args' in locals() else 'rtt_analysis.png'
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        print(f"\n生成分析报告: {output_path}")

#%%

# 删除测试代码和冗余注释
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='计算DNS RTT工具')
    parser.add_argument('pcap_file', help='PCAP文件路径')
    parser.add_argument('-o', '--output', default='rtt_analysis.png',
                        help='输出图片路径（默认: rtt_analysis.png）')
    args = parser.parse_args()
    
    if not os.path.isfile(args.pcap_file):
        print(f"错误: 文件 {args.pcap_file} 不存在")
        sys.exit(1)
        
    calculate_dns_rtt(args.pcap_file)

# %%
