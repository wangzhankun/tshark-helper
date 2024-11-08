#!/usr/bin/perl
use strict;
use warnings;
use threads;
use Thread::Queue;


# 计算每一个 tcp 流中， command 22(prepare stament) 和 command 25(close stament) 对的时间差
# 即为 mysql.resp 时间 

my $pcap_file = shift @ARGV;


# 检查是否提供了 PCAP 文件名
unless (defined $pcap_file) {
    die "Usage: $0 <pcap_file>\n";
}



print "Parsing PCAP file '$pcap_file'...\n";

# 读取 tshark 输出
my $tshark_output = `tshark -r '$pcap_file' -Y '(mysql.command == 22) or (mysql.command == 25)' -T fields -e frame.time_epoch -e tcp.stream -e mysql.command`;
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
    $streams{$stream} //= { command22 => [], command25 => [], time_intervals => [] };

    if ($stream == 0) {
        next;
    }

    if ($command == 22) {
        push @{$streams{$stream}->{command22}}, $timestamp;
    } elsif ($command == 25) {
        if (@{$streams{$stream}->{command22}}) {
            push @{$streams{$stream}->{command25}}, $timestamp;
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
        my $command22_times = $streams{$stream}->{command22};
        my $command25_times = $streams{$stream}->{command25};

        my $max_interval = 0;
        my @time_intervals;
        for my $i (0 .. $#{$command22_times}) {
            if (defined $command25_times->[$i]) {
                my $time_interval = $command25_times->[$i] - $command22_times->[$i];
                if ($time_interval < 0) {
                    print "Error: Negative time interval detected in stream $stream\n";
                } else {
                    push @time_intervals, $time_interval;
                    if ($time_interval > $max_interval) {
                        $max_interval = $time_interval;
                    }
                }
            }
        }

        # print "Stream $stream has max resp interval $max_interval\n";
        # 将结果放入结果队列
        $result_queue->enqueue([$stream, \@time_intervals, $max_interval]);
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
    my ($stream, $time_intervals, $max_interval) = @$result;
    $streams{$stream}->{time_intervals} = $time_intervals;
    $streams{$stream}->{max_interval} = $max_interval;
}

our $MAX_INTERVAL_ = 1;

print "如果有响应时间超过 $MAX_INTERVAL_ 秒的流，请查看输出。\n";

# 打印结果
foreach my $stream (keys %streams) {
    my $time_intervals = $streams{$stream}->{time_intervals};
    my $max_interval = $streams{$stream}->{max_interval};

    if ($max_interval > $MAX_INTERVAL_) {
        print "Stream $stream has long resp interval $max_interval\n";
    }
}