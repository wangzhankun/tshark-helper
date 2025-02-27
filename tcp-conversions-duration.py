import subprocess
import json
import numpy as np
import sys
import matplotlib
import argparse
import os

# 统计 tcp 流持续时间

def flag2bool(flag)->int:
    if flag == "True" or flag == "true":
        return 1
    return 0

# 定义提取TCP流开始和结束时间的函数
def extract_tcp_flow_times(pcap_file, mode='exact'):
    # 修改tshark命令根据模式
    if mode == 'exact':
        display_filter = "tcp.flags.syn==1 or tcp.flags.fin==1 or tcp.flags.reset==1"
    else:  # fuzzy模式
        display_filter = "tcp"

    command = [
        "tshark",
        "-r", pcap_file,
        "-T", "json",
        "-Y", display_filter,
        "-e", "tcp.stream",
        "-e", "frame.time_epoch",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.fin",
        "-e", "tcp.flags.reset"
    ]

    # 运行TShark命令
    result = subprocess.run(command, capture_output=True, text=True)
    data = json.loads(result.stdout)

    # 解析数据，提取每个TCP流的开始和结束时间
    flow_times = {}
    for packet in data:
        stream_id = packet["_source"]["layers"]["tcp.stream"][0]
        time_epoch = float(packet["_source"]["layers"]["frame.time_epoch"][0])
        syn_flag = flag2bool(packet["_source"]["layers"].get("tcp.flags.syn", [0])[0])
        fin_flag = flag2bool(packet["_source"]["layers"].get("tcp.flags.fin", [0])[0])
        reset_flag = flag2bool(packet["_source"]["layers"].get("tcp.flags.reset", [0])[0])

        if stream_id not in flow_times:
            flow_times[stream_id] = {
                "start": time_epoch if mode == 'fuzzy' else 0,
                "end": time_epoch,
                "syn_received": False
            }

        # 精确模式处理
        if mode == 'exact':
            if syn_flag and not flow_times[stream_id]["syn_received"]:
                flow_times[stream_id]["start"] = time_epoch
                flow_times[stream_id]["syn_received"] = True
                
            if (fin_flag or reset_flag) and flow_times[stream_id]["syn_received"]:
                if time_epoch > flow_times[stream_id]["end"]:
                    flow_times[stream_id]["end"] = time_epoch

        # 模糊模式处理
        else:
            # 始终更新开始时间为最早的时间戳
            if time_epoch < flow_times[stream_id]["start"]:
                flow_times[stream_id]["start"] = time_epoch
                
            # 始终更新结束时间为最晚的时间戳
            if time_epoch > flow_times[stream_id]["end"]:
                flow_times[stream_id]["end"] = time_epoch

    # 过滤无效数据
    valid_flows = {}
    for stream_id, data in flow_times.items():
        if mode == 'exact' and not data["syn_received"]:
            continue  # 精确模式跳过未完成握手的流
        if data["end"] > data["start"]:
            valid_flows[stream_id] = {
                "start": data["start"],
                "end": data["end"]
            }
    
    return valid_flows

# 计算持续时间并打印结果
def calculate_durations(flow_times)->(np.ndarray, dict):
    durations = []
    start2duration = {}
    for stream_id, times in flow_times.items():
        if times["start"] and times["end"]:
            duration = times["end"] - times["start"]
            durations.append(duration)
            start2duration[times["start"]] = duration
            # print(f"TCP Stream {stream_id}: Duration = {duration} seconds")
    
    # print min, max, avg of durations
       
    # 转换列表为numpy数组以便进行向量化操作
    durations = np.array(durations, dtype=np.float64)
    
    if durations.size > 0:
        min_duration = np.min(durations)
        max_duration = np.max(durations)
        avg_duration = np.mean(durations)
        
        # 计算分位数
        percentiles = [50, 90, 95, 99]
        percentile_values = np.percentile(durations, percentiles)
        print(f"TCP Stream connection duration statistics:")
        print(f"Avg Duration: {avg_duration:.15f} seconds")
        
        print(f"Min Duration: {min_duration:.15f} seconds")  # 控制输出的小数位数
        for p, value in zip(percentiles, percentile_values):
            print(f"{p}% Percentile: {value:.15f} seconds")
        print(f"Max Duration: {max_duration:.15f} seconds")
    
    return durations, start2duration



def gui_dashboard(durations: np.ndarray, start2duration: dict, name_prefix="output"):
    import pandas as pd
    import matplotlib.pyplot as plt
    import seaborn as sns
    from matplotlib.gridspec import GridSpec
    
    if durations.size == 0 or not start2duration:
        print("No data for dashboard")
        return

    # 准备数据
    df = pd.DataFrame({
        'start_time': pd.to_datetime(list(start2duration.keys()), unit='s'),
        'duration': durations
    }).sort_values('start_time')
    
    # 创建画布
    plt.close('all')
    fig = plt.figure(figsize=(20, 16), dpi=100)
    fig.suptitle(f'{name_prefix} - TCP Conversions Duration Analysis', fontsize=18, y=0.98)
    gs = GridSpec(3, 3, figure=fig, hspace=0.4, wspace=0.3)

    # ------------------
    # 左上：分布直方图
    # ------------------
    ax1 = fig.add_subplot(gs[0, 0])
    sns.histplot(df['duration'], bins=50, kde=True, ax=ax1, color='#1f77b4')
    ax1.set_title('1. Duration Distribution', pad=15, fontsize=14)
    ax1.set_xlabel('Duration (seconds)', fontsize=12)
    ax1.set_ylabel('Count', fontsize=12)
    ax1.grid(True, linestyle='--', alpha=0.7)

    # 添加统计标注
    stats_text = f"""Entries: {len(df):,}
Mean: {df.duration.mean():.2f}s
Std Dev: {df.duration.std():.2f}s
95th%: {df.duration.quantile(0.95):.2f}s"""
    ax1.text(0.98, 0.75, stats_text, 
            transform=ax1.transAxes,
            ha='right', va='top',
            bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))

    # ------------------
    # 中上：箱线图
    # ------------------
    ax2 = fig.add_subplot(gs[0, 1])
    sns.boxplot(x=df['duration'], ax=ax2, color='#2ca02c', width=0.3)
    ax2.set_title('2. Duration Spread', pad=15, fontsize=14)
    ax2.set_xlabel('Duration (seconds)', fontsize=12)
    ax2.grid(True, linestyle='--', alpha=0.7)

    # ------------------
    # 右上：累积分布
    # ------------------
    ax3 = fig.add_subplot(gs[0, 2])
    sorted_duration = np.sort(durations)
    cdf = np.arange(1, len(sorted_duration)+1) / len(sorted_duration)
    ax3.plot(sorted_duration, cdf, color='#d62728', lw=2)
    ax3.set_title('3. Cumulative Distribution', pad=15, fontsize=14)
    ax3.set_xlabel('Duration (seconds)', fontsize=12)
    ax3.set_ylabel('Probability', fontsize=12)
    ax3.grid(True, linestyle='--', alpha=0.7)
    ax3.set_ylim(0, 1.05)

    # ------------------
    # 下部：时间序列分析（占满两行宽度）
    # ------------------
    ax4 = fig.add_subplot(gs[1:3, :])
    
    # 散点图（原始数据）
    sc = ax4.scatter(
        df['start_time'], 
        df['duration'],
        c=df['duration'],
        cmap='viridis',
        s=25,
        alpha=0.5,
        edgecolors='w',
        linewidth=0.5,
        label='Individual Connections'
    )

    # 移动平均线
    window_size = max(1, len(df)//50)
    df['ma'] = df['duration'].rolling(window=window_size, min_periods=1).mean()
    ax4.plot(
        df['start_time'], 
        df['ma'], 
        color='red',
        lw=2,
        label=f'{window_size}-Connection Moving Average'
    )

    # 异常值标注（前5个超过95%分位数的点）
    threshold = df['duration'].quantile(0.95)
    outliers = df[df['duration'] > threshold].head(5)
    for idx, row in outliers.iterrows():
        ax4.annotate(
            f"{row['duration']:.1f}s",
            (row['start_time'], row['duration']),
            textcoords="offset points",
            xytext=(0,10),
            ha='center',
            color='darkred',
            arrowprops=dict(arrowstyle="->", color='darkred')
        )

    # 时间轴格式化
    ax4.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%m/%d %H:%M:%S'))
    ax4.xaxis.set_major_locator(plt.matplotlib.dates.AutoDateLocator())
    plt.xticks(rotation=45, ha='right')
    
    # 公共设置
    ax4.set_title('4. Connection Duration Timeline', pad=15, fontsize=14)
    ax4.set_ylabel('Duration (seconds)', fontsize=12)
    ax4.set_xlabel('Connection Start Time', fontsize=12)
    ax4.grid(True, linestyle='--', alpha=0.5)
    ax4.legend(loc='upper left', frameon=True)
    
    # 颜色条
    cbar = plt.colorbar(sc, ax=ax4)
    cbar.set_label('Duration (seconds)', rotation=270, labelpad=20)

    # 调整布局
    plt.tight_layout(rect=[0, 0, 1, 0.96])
    output_path = f'./{name_prefix}_dashboard.png'
    plt.savefig(output_path)
    print(f"仪表盘已保存至: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='TCP流持续时间分析工具')
    parser.add_argument('pcap_file', help='PCAP文件路径')
    parser.add_argument('--mode', choices=['exact', 'fuzzy'], default='exact',
                       help='分析模式: exact-精确模式（默认）, fuzzy-模糊模式')
    parser.add_argument('--name', type=str, default=None,
                       help='输出图表名称前缀（默认使用pcap文件名）')
    args = parser.parse_args()

    # 自动生成默认名称
    if args.name is None:
        base_name = os.path.splitext(os.path.basename(args.pcap_file))[0]
        args.name = base_name

    flow_times = extract_tcp_flow_times(args.pcap_file, args.mode)
    print(f"分析模式: {args.mode}")
    print(f"发现有效TCP流数量: {len(flow_times)}")
    
    durations, start2duration = calculate_durations(flow_times)
    print(f"Total durations: {len(durations)}")
    print(f"Sample durations: {durations[:5]}")
    
    # gui_durations(durations)
    # gui_start2duration(start2duration)
    # gui_combined_analysis(durations, start2duration)
    gui_dashboard(durations, start2duration, name_prefix=args.name)
