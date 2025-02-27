import subprocess
import json
import numpy as np
import sys
import matplotlib

# 统计 tcp 流持续时间

def flag2bool(flag)->int:
    if flag == "True" or flag == "true":
        return 1
    return 0

# 定义提取TCP流开始和结束时间的函数
def extract_tcp_flow_times(pcap_file):
    # 使用tshark过滤SYN/FIN/RST标志包
    # 记录每个stream_id的最早SYN时间和最晚FIN/RST时间
    # 注意：这里假设每个流都有完整的握手和终止过程

    # 构建TShark命令
    command = [
        "tshark",
        "-r", pcap_file,
        "-T", "json",
        "-Y", "tcp.flags.syn==1 or tcp.flags.fin==1 or tcp.flags.reset==1",
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
        syn_flag = flag2bool(packet["_source"]["layers"]["tcp.flags.syn"][0]) 
        fin_flag = flag2bool(packet["_source"]["layers"]["tcp.flags.fin"][0])
        reset_flag = flag2bool(packet["_source"]["layers"]["tcp.flags.reset"][0]) 

        if stream_id not in flow_times:
            flow_times[stream_id] = {"start": 0, "end": 0}
        
        # 检查SYN标志，记录开始时间
        if syn_flag == 1 and flow_times[stream_id]["start"] == 0:
            flow_times[stream_id]["start"] = time_epoch
        
        # 检查FIN或RST标志，记录结束时间
        if (fin_flag == 1 or reset_flag == 1) and (time_epoch > flow_times[stream_id]["end"]):
            flow_times[stream_id]["end"] = time_epoch

    return flow_times

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

def gui_durations(durations: np.ndarray):
    # 在函数开头添加详细数据检查
    if durations.size == 0:
        print("Error: Empty duration data")
        return
    print(f"Debug info - Data stats:")
    print(f"Data points: {len(durations)}")
    print(f"Min: {np.min(durations):.2f}, Max: {np.max(durations):.2f}")
    print(f"NaN values: {np.isnan(durations).sum()}")
    
    # 在函数开头添加后端设置
    matplotlib.use('WebAgg')  # 生成网页交互式图表
    
    # 原有导入保持不变...
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns
    except ImportError as e:
        print(f"Required library missing: {e}")
        print("Please install dependencies with: pip install seaborn matplotlib pandas numpy")
        return
    
    if durations.size == 0:
        print("No duration data to plot")
        return

    # 设置专业绘图样式
    sns.set(style="whitegrid", font_scale=1.2)
    plt.figure(figsize=(12, 6), dpi=100, facecolor='white')  # 添加背景色
    ax1 = plt.gca()
    ax2 = ax1.twinx()

    # 绘制直方图
    n, bins, patches = ax1.hist(
        durations, 
        bins=50,
        edgecolor='black',
        alpha=0.7,
        color=sns.color_palette("Blues")[2],
        label='Count'
    )

    # 添加对数坐标曲线
    ax2.hist(
        durations,
        bins=50,
        cumulative=False,
        histtype='step',
        color='darkred',
        linewidth=2,
        density=True,
        label='Density'
    )

    # 标注关键统计量
    stats_text = f"""
    Min: {np.min(durations):.1f}s
    Max: {np.max(durations):.1f}s
    Mean: {np.mean(durations):.1f}s
    95th%: {np.percentile(durations, 95):.1f}s"""
    plt.text(0.75, 0.95, stats_text, 
             transform=ax1.transAxes,
             bbox=dict(facecolor='white', alpha=0.8))

    # 设置坐标轴标签
    ax1.set_xlabel('Duration (seconds)', fontsize=12)
    ax1.set_ylabel('Frequency (Count)', color='navy', fontsize=12)
    ax2.set_ylabel('Probability Density', color='darkred', fontsize=12)
    
    # 设置刻度格式
    ax1.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f"{int(x):,}"))
    ax1.tick_params(axis='y', labelcolor='navy')
    ax2.tick_params(axis='y', labelcolor='darkred')
    
    plt.title('TCP Connection Duration Distribution', fontsize=14, pad=20)
    plt.tight_layout()
    
    # 在plt.show()前添加保存功能
    plt.savefig('/tmp/duration_plot.png')  # 调试用
    print("Plot saved to /tmp/duration_plot.png")
    
    plt.show()



def gui_start2duration(start2duration: dict):
    import pandas as pd
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib import cm
    import seaborn as sns

    if not start2duration:
        print("No duration data to plot")
        return

    # 准备数据
    df = pd.DataFrame.from_dict(
        start2duration, 
        orient='index', 
        columns=['duration']
    ).reset_index()
    df.columns = ['start_time', 'duration']
    df['start_time'] = pd.to_datetime(df['start_time'], unit='s')
    df = df.sort_values('start_time')

    # 创建画布
    sns.set(style="darkgrid")
    fig, ax = plt.subplots(figsize=(14, 7), dpi=100)

    # 使用颜色映射表示持续时间长短
    sc = ax.scatter(
        df['start_time'], 
        df['duration'],
        c=df['duration'],
        cmap='viridis',
        s=20,
        alpha=0.6,
        edgecolors='w',
        linewidth=0.3
    )

    # 添加趋势线（移动平均）
    window_size = max(1, len(df) // 20)  # 自动调整窗口大小
    df['ma'] = df['duration'].rolling(
        window=window_size, 
        min_periods=1
    ).mean()
    ax.plot(
        df['start_time'], 
        df['ma'], 
        color='red',
        linewidth=2,
        label=f'{window_size}-point Moving Average'
    )

    # 时间轴格式化
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M\n%m-%d'))
    ax.xaxis.set_major_locator(mdates.AutoDateLocator())
    
    # 颜色条设置
    cbar = plt.colorbar(sc, ax=ax)
    cbar.set_label('Duration (seconds)', rotation=270, labelpad=15)

    # 标签设置
    ax.set_ylabel('Duration (seconds)', fontsize=12)
    ax.set_xlabel('Connection Start Time', fontsize=12)
    ax.set_title('TCP Connection Durations Over Time', fontsize=14, pad=15)
    
    # 优化刻度
    plt.xticks(rotation=45, ha='right')
    plt.yticks(np.arange(0, df['duration'].max()+10, 10))
    
    # 添加图例
    ax.legend(loc='upper left', frameon=True)
    
    plt.tight_layout()
    plt.show()

def gui_combined_analysis(durations: np.ndarray, start2duration: dict):
    import pandas as pd
    import matplotlib.pyplot as plt
    import seaborn as sns
    
    if durations.size == 0 or not start2duration:
        print("No data for combined analysis")
        return

    # 准备数据
    df = pd.DataFrame({
        'start_time': pd.to_datetime(list(start2duration.keys()), unit='s'),
        'duration': durations
    })

    # 创建画布
    sns.set(style="ticks")
    fig = plt.figure(figsize=(16, 10), dpi=100)
    gs = fig.add_gridspec(2, 2)

    # 子图1：分布直方图
    ax1 = fig.add_subplot(gs[0, 0])
    sns.histplot(df['duration'], bins=50, kde=True, ax=ax1, color='teal')
    ax1.set_title('Duration Distribution')
    ax1.set_xlabel('Duration (seconds)')
    ax1.set_ylabel('Count')

    # 子图2：箱线图
    ax2 = fig.add_subplot(gs[0, 1])
    sns.boxplot(x=df['duration'], ax=ax2, color='skyblue')
    ax2.set_title('Duration Spread')
    ax2.set_xlabel('Duration (seconds)')

    # 子图3：时间序列分析
    ax3 = fig.add_subplot(gs[1, :])
    df.set_index('start_time')['duration'].plot(
        style='.', 
        markersize=8,
        alpha=0.5,
        ax=ax3,
        color='purple'
    )
    ax3.set_title('Duration Time Series')
    ax3.set_ylabel('Duration (seconds)')
    ax3.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%H:%M\n%m-%d'))
    
    plt.tight_layout()
    plt.show()

def gui_dashboard(durations: np.ndarray, start2duration: dict):
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
    fig.suptitle('TCP Connection Analysis Dashboard', fontsize=18, y=0.98)
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
    ax4.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%m/%d %H:%M'))
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
    plt.savefig('./duration_dashboard.png')  # 调试用
    # plt.show()

if __name__ == "__main__":
        # 检查是否提供了正确的参数数量
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_pcap_file>")
        sys.exit(1)
    # pcap_file = "/Users/bytedance/Downloads/9.27-normal.pcap"
    # pcap_file = "/Users/bytedance/Downloads/9.26_bad.pcap"
    pcap_file = sys.argv[1]  # 假设传入了PCAP文件的路径作为参数

    flow_times = extract_tcp_flow_times(pcap_file)
    durations, start2duration = calculate_durations(flow_times)
    print(f"Total durations: {len(durations)}")
    print(f"Sample durations: {durations[:5]}")
    
    # gui_durations(durations)
    # gui_start2duration(start2duration)
    # gui_combined_analysis(durations, start2duration)
    gui_dashboard(durations, start2duration)