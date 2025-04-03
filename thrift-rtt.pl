#!/usr/bin/perl
use strict;
use warnings;
use threads;
use Thread::Queue;
use List::Util qw(sum);


# 计算每一个 tcp 流中， thrift.mtype == 1 (call) 和 thrift.mtype == 2 (reply) 对的时间差
# 即为 thrift.resp 时间 

my $pcap_file = shift @ARGV;


# 检查是否提供了 PCAP 文件名
unless (defined $pcap_file) {
    die "Usage: $0 <pcap_file>\n";
}



print "Parsing PCAP file '$pcap_file'...\n";

# 读取 tshark 输出
my $tshark_output = `tshark -r '$pcap_file' -Y '(thrift.mtype == 1) or (thrift.mtype == 2)' -T fields -e frame.time_epoch -e tcp.stream -e thrift.mtype`;
if ($? != 0) {
    print "Error: tshark command failed\n";
    exit;
}
print "Parsing tshark output...\n";

my %streams;


# 处理 tshark 输出
foreach my $line (split /\n/, $tshark_output) {
    my ($timestamp, $stream, $command) = split /\t/, $line;

    # 只处理 TCP 流
    next unless defined $stream;

    # 初始化流
    $streams{$stream} //= { call => [], reply => [], time_intervals => [] };

    if ($stream == 0) {
        next;
    }

    # 将十六进制字符串转换为十进制数值
    if (hex($command) == 1) {
        push @{$streams{$stream}->{call}}, $timestamp;
    } elsif (hex($command) == 2) {
        if (@{$streams{$stream}->{call}}) {
            push @{$streams{$stream}->{reply}}, $timestamp;
        }
    }
}


# print size of streams
print "Number of streams: ", scalar keys %streams, "\n";

# 创建线程队列
my $queue = Thread::Queue->new();
my $result_queue = Thread::Queue->new();

# 将流添加到队列
foreach my $stream (keys %streams) {
    $queue->enqueue($stream);
}
$queue->end();

# 定义线程处理函数
sub process_stream {

    # my $thread_id = threads->tid();  # 获取当前线程的 ID
    # print "Thread $thread_id started\n";

    while (defined(my $stream = $queue->dequeue())) {
        my $call_times = $streams{$stream}->{call};
        my $reply_times = $streams{$stream}->{reply};

        my $max_interval = 0;
        my @time_intervals;
        my @time_start_list;
        for my $i (0 .. $#{$call_times}) {
            if (defined $reply_times->[$i]) {
                my $time_interval = $reply_times->[$i] - $call_times->[$i];
                if ($time_interval < 0) {
                    print "Error: Negative time interval detected in stream $stream\n";
                } else {
                    push @time_intervals, $time_interval;
                    push @time_start_list, $call_times->[$i];
                    if ($time_interval > $max_interval) {
                        $max_interval = $time_interval;
                    }
                }
            }
        }

        # print "Stream $stream has max resp interval $max_interval\n";
        # 将结果放入结果队列
        $result_queue->enqueue([$stream, \@time_intervals, \@time_start_list, $max_interval]);
    }
    # print "Thread $thread_id finished\n";
}

# 创建多个线程
my @threads;
for (1 .. 8) {  # 根据需要调整线程数量
    push @threads, threads->create(\&process_stream);
}

# 等待所有线程完成
$_->join() for @threads;
# 线程完成后，结束结果队列
$result_queue->end();

# 收集结果
while (defined(my $result = $result_queue->dequeue())) {
    my ($stream, $time_intervals, $time_start_list, $max_interval) = @$result;
    $streams{$stream}->{time_intervals} = $time_intervals;
    $streams{$stream}->{time_start_list} = $time_start_list;
    $streams{$stream}->{max_interval} = $max_interval;
}

our $MAX_INTERVAL_ = 0.001; # 单位秒

print "如果有响应时间超过 $MAX_INTERVAL_ 秒的流，请查看输出。\n";


foreach my $stream (keys %streams) {
    my $time_intervals = $streams{$stream}->{time_intervals};
    my $max_interval = $streams{$stream}->{max_interval};
    my $time_start_list = $streams{$stream}->{time_start_list};
    
    # if ($max_interval > $MAX_INTERVAL_) {
    #     print "Stream $stream has long resp interval $max_interval\n";
    # }
    
    # 计算平均时延
    if (@$time_intervals) {
        my $avg_delay = sum(@$time_intervals) / scalar(@$time_intervals);
        printf("  Average delay: %.6f s (based on %d samples)\n", $avg_delay, scalar(@$time_intervals));
        
        # 可选：输出时间分布
        my $sorted = [sort { $a <=> $b } @$time_intervals];
        printf("  P95: %.6f s\n", $sorted->[int(0.95*$#$sorted)]);
        printf("  P99: %.6f s\n", $sorted->[int(0.99*$#$sorted)]);
        printf("  MAX: %.6f s\n", $sorted->[$#$sorted]);
    } else {
        print "  No valid time intervals for average calculation\n";
    }
}