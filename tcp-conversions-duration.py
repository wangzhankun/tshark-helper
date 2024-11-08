import subprocess
import json
import numpy as np
import sys

# 统计 tcp 流持续时间

def flag2bool(flag)->int:
    if flag == "True" or flag == "true":
        return 1
    return 0

# 定义提取TCP流开始和结束时间的函数
def extract_tcp_flow_times(pcap_file):
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
    # 将 durations 向下取整到最近的 5 秒
    durations = np.floor(durations).astype(int) // 5 * 5
    # 统计每个持续时间出现的次数
    counts = np.bincount(durations)
    # 绘制 直方图
    import matplotlib.pyplot as plt
    plt.xlabel('Duration (seconds)')
    plt.ylabel('Frequency')
    plt.hist(durations, bins=range(0, 101, 5), edgecolor='black')
    plt.show()



def gui_start2duration(start2duration: dict):
    import pandas as pd
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates

    # 假设您的字典是 data_dict = {timestamp1: duration1, timestamp2: duration2, ...}
    # 将字典转换为 pandas 的 DataFrame
    data = pd.DataFrame.from_dict(start2duration, orient='index', columns=['duration'])
    data.index = pd.to_datetime(data.index, unit='s')  # 将时间戳转换为 datetime 格式

    # 创建一个新的 figure 和 axes 对象
    fig, ax = plt.subplots(figsize=(12, 6))

    # 绘制散点图
    ax.scatter(data.index, data['duration'], s=10, alpha=0.3)

    # 设置 x 轴的格式化
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))  # 将 x 轴标签设置为 time of day 格式
    plt.xticks(rotation=45)  # 旋转 x 轴标签防止重叠

    label_interval = int((data.index.max() - data.index.min()).total_seconds() // 20)
    ax.xaxis.set_major_locator(mdates.SecondLocator(interval=label_interval))  # 设置 x 轴标签的间隔为 600 秒
    ax.set_xlim(data.index.min(), data.index.max())  # 设置 x 轴的范围

    # 设置 y 轴的标签
    ax.set_ylabel('Duration')

    # 设置标题
    ax.set_title('Scatter Plot of Durations')

    # 显示网格
    ax.grid(True)


    # 调整图像边距以防止标签被剪切
    plt.tight_layout()

    # 显示图像
    plt.show()

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
    gui_durations(durations)
    gui_start2duration(start2duration)